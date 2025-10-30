import sqlite3, re, json
import pandas as pd
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from gensim import corpora, models
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np

try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords')
try:
    nltk.data.find('corpora/wordnet')
except LookupError:
    nltk.download('wordnet')

DB_FILE = "database.sqlite"

# 1) load posts and comments
conn = sqlite3.connect(DB_FILE)
posts = pd.read_sql_query("SELECT id, content AS post_text FROM posts ORDER BY id", conn)
comments = pd.read_sql_query("SELECT post_id, content AS comment_text FROM comments ORDER BY post_id", conn)
conn.close()

# combine comments with their post (one document per post)
cmts = comments.groupby("post_id")["comment_text"].apply(lambda s: " ".join(s.dropna())).reset_index()
docs = posts.merge(cmts, left_on="id", right_on="post_id", how="left")
docs["comment_text"] = docs["comment_text"].fillna("")
docs["full_text"] = (docs["post_text"].fillna("") + " " + docs["comment_text"]).str.strip()

if docs["full_text"].str.len().sum() == 0:
    print("No text found. Stop.")
    raise SystemExit

# 2) clean text
stop_words = set(stopwords.words("english"))
lemm = WordNetLemmatizer()
pat = re.compile(r"[a-z]+")

# extra stopwords to remove filler and very common verbs
extra_stop = {
    "get","got","make","let","keep","really","much","something",
    "come","take","say","use","also","maybe","try","trying","like","lot"
}
stop_words |= extra_stop

def preprocess(text: str):
    text = text.lower()
    words = pat.findall(text)
    out = []
    for w in words:
        if w in stop_words:
            continue
        if len(w) < 3:
            continue
        out.append(lemm.lemmatize(w))
    return out

print("Cleaning text ...")
tokens = [preprocess(t) for t in docs["full_text"].tolist()]

# drop empty documents
clean_docs, doc_ids = [], []
for i, t in enumerate(tokens):
    if t:
        clean_docs.append(t)
        doc_ids.append(i)

if not clean_docs:
    print("No valid documents after cleaning.")
    raise SystemExit

print(f"After cleaning: {len(clean_docs)} documents\n")

# 3) build dictionary and corpus
dictionary = corpora.Dictionary(clean_docs)
n = len(clean_docs)
dictionary.filter_extremes(no_below=(2 if n < 80 else 5), no_above=(0.7 if n < 80 else 0.5))
if len(dictionary) == 0:
    print("Dictionary is empty. Stop.")
    raise SystemExit

corpus = [dictionary.doc2bow(t) for t in clean_docs]

# 4) train LDA
print("Training LDA with 10 topics ...\n")
NUM_TOPICS = 10
lda = models.LdaModel(
    corpus=corpus,
    id2word=dictionary,
    num_topics=NUM_TOPICS,
    passes=10,
    alpha="auto",
    eta="auto",
    random_state=42,
)

# 5) topic words and prevalence
topics = []
topic_mass = [0.0] * NUM_TOPICS
for bow in corpus:
    for k, p in lda.get_document_topics(bow, minimum_probability=0.0):
        topic_mass[k] += p
total = sum(topic_mass) or 1.0

for k in range(NUM_TOPICS):
    words = [w for w, _ in lda.show_topic(k, topn=8)]
    topics.append({
        "topic_num": k + 1,
        "top_words": words,
        "prevalence_%": round(100 * topic_mass[k] / total, 2),
    })

topics.sort(key=lambda x: x["prevalence_%"], reverse=True)

# 6) pick representative posts
doc_map = docs.iloc[doc_ids][["id", "post_text"]].reset_index(drop=True)
rep = {k: [] for k in range(NUM_TOPICS)}
for i, bow in enumerate(corpus):
    dist = lda.get_document_topics(bow, minimum_probability=0.0)
    dom_k, dom_p = max(dist, key=lambda x: x[1])
    pid = int(doc_map.loc[i, "id"])
    txt = (doc_map.loc[i, "post_text"] or "").strip()
    rep[dom_k].append((dom_p, pid, txt))

for k in rep:
    rep[k].sort(key=lambda x: x[0], reverse=True)
    rep[k] = rep[k][:3]

def short(t: str, n: int = 85):
    t = (t or "").replace("\n", " ").strip()
    return t[:n] + ("..." if len(t) > n else "")

# 7) auto labels (basic and TF-IDF smart)
for t in topics:
    t["auto_label_basic"] = " / ".join(t["top_words"][:3]).title()

texts = [" ".join(t["top_words"]) for t in topics]
tfidf = TfidfVectorizer(stop_words="english")
tfidf_matrix = tfidf.fit_transform(texts)
feature_names = np.array(tfidf.get_feature_names_out())

smart_labels = []
for row in tfidf_matrix:
    idxs = np.argsort(row.toarray()).flatten()[::-1][:3]
    smart_labels.append(" / ".join(feature_names[idxs]).title())

for i, lbl in enumerate(smart_labels):
    topics[i]["auto_label_smart"] = lbl

# 8) print results
print("=" * 80)
print("10 MOST DISCUSSED TOPICS ON MINI SOCIAL")
print("Topics are based on word distribution and representative posts")
print("=" * 80)
for t in topics:
    k, pct = t["topic_num"], t["prevalence_%"]
    words = ", ".join(t["top_words"])
    print(f"\nTopic {k} ({pct:.2f}% of platform)")
    print(f"  Top words: {words}")
    print(f"  Label: {t['auto_label_smart']}")
    print("  Example posts:")
    for p, pid, txt in rep[k - 1]:
        print(f"    - Post #{pid} (match {p:.2f}): {short(txt)}")

# 9) summary table
summary_df = pd.DataFrame(topics)[["topic_num", "prevalence_%", "auto_label_smart", "top_words"]]
print("\n" + "=" * 80)
print("SUMMARY TABLE\n")
print(summary_df.to_string(index=False))

# 10) save model and labels
lda.save("lda_model.pkl")
dictionary.save("lda_dictionary.pkl")

labels_payload = {
    str(i): {
        "label": topics[i]["auto_label_smart"],
        "top_words": topics[i]["top_words"]
    }
    for i in range(NUM_TOPICS)
}
with open("topic_labels.json", "w", encoding="utf-8") as f:
    json.dump(labels_payload, f, ensure_ascii=False, indent=2)

print("\nSaved: lda_model.pkl, lda_dictionary.pkl, topic_labels.json")
