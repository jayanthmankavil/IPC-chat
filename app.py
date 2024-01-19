import os
os.environ['KMP_DUPLICATE_LIB_OK']='True'
from flask import Flask, request, render_template, redirect, url_for, session
from sentence_transformers import SentenceTransformer, util
import pandas as pd
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key' 


def load_ipc_dataset_updated(file_path):
    ipc_data = pd.read_csv(file_path)
    ipc_descriptions = ipc_data['Full Description'].tolist()
    return ipc_data, ipc_descriptions

def create_embeddings(model, descriptions):
    return model.encode(descriptions, convert_to_tensor=True)

def standardize_ipc_section(query):
    match = re.search(r'ipc\s*[-_]*\s*(\d+)', query, re.I)
    if match:
        return f"IPC_{match.group(1)}"
    return None

def get_query_type_updated(query):
    query = query.lower()
    if "simple" in query or "what is" in query:
        return "Simple Words"
    elif "detail" in query or "explain" in query:
        return "Full Description"
    elif "punishment" in query:
        return "Punishment"
    elif "offense" in query or "offence" in query:
        return "Offense"
    else:
        return "Simple Words"

def find_relevant_ipc_section_updated(query, model, ipc_data, ipc_embeddings):
    query_type = get_query_type_updated(query)
    standardized_section = standardize_ipc_section(query)

    if standardized_section:
        direct_match = ipc_data[ipc_data['Section'].str.contains(standardized_section, case=False, na=False)]
        if not direct_match.empty:
            return direct_match.iloc[0][query_type]

    query_embedding = model.encode(query, convert_to_tensor=True)
    similarity_scores = util.pytorch_cos_sim(query_embedding, ipc_embeddings)[0]
    highest_score_index = similarity_scores.argmax().item()
    return ipc_data.iloc[highest_score_index][query_type]


model = SentenceTransformer('all-MiniLM-L6-v2')
file_path = 'cleaned.csv'  
ipc_data, ipc_descriptions = load_ipc_dataset_updated(file_path)
ipc_embeddings = create_embeddings(model, ipc_descriptions)

@app.route('/', methods=['GET'])
def index():
    return render_template('chat.html', messages=session.get('messages', []))

@app.route('/query', methods=['POST'])
def query_ipc():
    user_query = request.form['user_query']
    last_discussed_section = session.get('last_discussed_section')

    
    if 'messages' not in session:
        session['messages'] = []
    session['messages'].append({'text': user_query, 'type': 'user-message'})

    
    new_section = standardize_ipc_section(user_query)
    if new_section:
        last_discussed_section = new_section
        session['last_discussed_section'] = last_discussed_section
        relevant_info = find_relevant_ipc_section_updated(user_query, model, ipc_data, ipc_embeddings)
    elif not new_section and last_discussed_section and "explain" in user_query.lower():
    
        relevant_info = ipc_data[ipc_data['Section'] == last_discussed_section]['Full Description'].iloc[0]
    else:
        relevant_info = find_relevant_ipc_section_updated(user_query, model, ipc_data, ipc_embeddings)

    
    session['messages'].append({'text': relevant_info, 'type': 'bot-message'})

    session.modified = True
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
