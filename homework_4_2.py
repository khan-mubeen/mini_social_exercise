import sqlite3, json, re
import pandas as pd
import numpy as np
import nltk
from nltk.sentiment import SentimentIntensityAnalyzer
from gensim import corpora, models
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer

try:
    nltk.data.find("sentiment/vader_lexicon.zip")
except LookupError:
    nltk.download("vader_lexicon")

DB_FILE = "database.sqlite"

print("=" * 80)
print("EXERCISE 4.2: VADER SENTIMENT ANALYSIS")
print("=" * 80)

# 1) load saved LDA model, dictionary, and labels
print("\nStep 1: Loading model, dictionary, and labels from Exercise 4.1 ...")
try:
    lda = models.LdaModel.load("lda_model.pkl")
    dictionary = corpora.Dictionary.load("lda_dictionary.pkl")
    print(f"Loaded LDA with {lda.num_topics} topics")
except FileNotFoundError:
    print("Model files not found. Please run Exercise 4.1 first.")
    raise SystemExit

# try to load labels json. If missing, create simple labels from the model.
labels_map = {}
try:
    with open("topic_labels.json", "r", encoding="utf-8") as f:
        raw = json.load(f)
        labels_map = {int(k): v["label"] for k, v in raw.items()}
    print("Loaded topic_labels.json")
except Exception:
    print("topic_labels.json not found. Will derive labels from top words.")
    labels_map = {
        k: " / ".join([w for w, _ in lda.show_topic(k, topn=3)]).title()
        for k in range(lda.num_topics)
    }

# 2) load posts and comments
print("\nStep 2: Loading posts and comments ...")
conn = sqlite3.connect(DB_FILE)
posts_df = pd.read_sql_query(
    "SELECT id, user_id, content, created_at FROM posts WHERE content IS NOT NULL AND content != ''",
    conn
)
comments_df = pd.read_sql_query(
    "SELECT id, post_id, user_id, content, created_at FROM comments WHERE content IS NOT NULL AND content != ''",
    conn
)
print(f"Posts: {len(posts_df)}  |  Comments: {len(comments_df)}")

# 3) initialize VADER and scoring helper
print("\nStep 3: Initializing VADER ...")
sia = SentimentIntensityAnalyzer()

def analyze_text_sentiment(text: str):
    scores = sia.polarity_scores(text)
    comp = scores["compound"]
    if comp >= 0.05:
        cat = "positive"
    elif comp <= -0.05:
        cat = "negative"
    else:
        cat = "neutral"
    return comp, cat, scores["pos"], scores["neu"], scores["neg"]

# 4) score posts
print("\nStep 4: Scoring posts ...")
post_rows = []
for _, row in posts_df.iterrows():
    comp, cat, pos, neu, neg = analyze_text_sentiment(row["content"])
    post_rows.append({
        "post_id": row["id"],
        "user_id": row["user_id"],
        "content": row["content"],
        "compound": comp,
        "category": cat,
        "pos": pos,
        "neu": neu,
        "neg": neg,
    })
posts_sentiment_df = pd.DataFrame(post_rows)

# 5) score comments
print("Step 5: Scoring comments ...")
comment_rows = []
for _, row in comments_df.iterrows():
    comp, cat, pos, neu, neg = analyze_text_sentiment(row["content"])
    comment_rows.append({
        "comment_id": row["id"],
        "post_id": row["post_id"],
        "compound": comp,
        "category": cat,
        "pos": pos,
        "neu": neu,
        "neg": neg,
    })
comments_sentiment_df = pd.DataFrame(comment_rows)

# 6) overall platform tone
print("\n" + "=" * 80)
print("OVERALL PLATFORM TONE")
print("=" * 80)
all_scores = list(posts_sentiment_df["compound"]) + list(comments_sentiment_df["compound"])
overall_mean = float(np.mean(all_scores)) if all_scores else 0.0
total_items = len(posts_sentiment_df) + len(comments_sentiment_df)

combined_cats = pd.concat([posts_sentiment_df["category"], comments_sentiment_df["category"]]).value_counts() if total_items else pd.Series(dtype=int)

print(f"\nTotal analyzed: {total_items} items")
print(f"  Posts: {len(posts_sentiment_df)}")
print(f"  Comments: {len(comments_sentiment_df)}")
print(f"\nAverage sentiment score: {overall_mean:.4f}")
if overall_mean >= 0.05:
    tone = "POSITIVE"
elif overall_mean <= -0.05:
    tone = "NEGATIVE"
else:
    tone = "NEUTRAL"
print(f"Overall platform tone: {tone}")

print("\nSentiment distribution:")
for cat in ["positive", "neutral", "negative"]:
    c = int(combined_cats.get(cat, 0))
    pct = (c / total_items * 100) if total_items else 0.0
    print(f"  {cat.capitalize():<8}: {c:4d} ({pct:5.2f}%)")

pm = float(posts_sentiment_df["compound"].mean()) if len(posts_sentiment_df) else 0.0
cm = float(comments_sentiment_df["compound"].mean()) if len(comments_sentiment_df) else 0.0
print("\nPosts vs Comments:")
print(f"  Average post sentiment    : {pm:+.4f}")
print(f"  Average comment sentiment : {cm:+.4f}")

# 7) map posts to topics using saved dictionary (same preprocessing rules as 4.1)
print("\n" + "=" * 80)
print("SENTIMENT BY TOPIC FROM EXERCISE 4.1")
print("=" * 80)

# prepare post+comment documents (same construction as 4.1)
posts_full = pd.read_sql_query("SELECT id, content AS post_text FROM posts ORDER BY id", conn)
comments_full = pd.read_sql_query("SELECT post_id, content AS comment_text FROM comments ORDER BY post_id", conn)
conn.close()

cmts = comments_full.groupby("post_id")["comment_text"].apply(lambda s: " ".join(s.dropna())).reset_index()
docs = posts_full.merge(cmts, left_on="id", right_on="post_id", how="left")
docs["comment_text"] = docs["comment_text"].fillna("")
docs["full_text"] = (docs["post_text"].fillna("") + " " + docs["comment_text"]).str.strip()

# same preprocessing as 4.1
stop_words = set(stopwords.words("english"))
extra_stop = {
    "get","got","make","let","keep","really","much","something",
    "come","take","say","use","also","maybe","try","trying","like","lot"
}
stop_words |= extra_stop
lemm = WordNetLemmatizer()
pat = re.compile(r"[a-z]+")

def preprocess(text: str):
    text = text.lower()
    words = pat.findall(text)
    return [lemm.lemmatize(w) for w in words if w not in stop_words and len(w) >= 3]

tokens = [preprocess(t) for t in docs["full_text"].tolist()]

# build corpus with the saved dictionary
clean_idx = []
clean_tokens = []
for i, t in enumerate(tokens):
    if t:
        clean_idx.append(i)
        clean_tokens.append(t)

corpus = [dictionary.doc2bow(t) for t in clean_tokens]

# map each post to its dominant topic
post_to_topic = {}
for i, bow in enumerate(corpus):
    dist = lda.get_document_topics(bow, minimum_probability=0.0)
    if not dist:
        continue
    dom_k, dom_p = max(dist, key=lambda x: x[1])
    post_id = int(docs.iloc[clean_idx[i]]["id"])
    post_to_topic[post_id] = dom_k  # zero based

# join topic id to post sentiment
posts_sentiment_df["topic_id"] = posts_sentiment_df["post_id"].map(post_to_topic)
posts_with_topics = posts_sentiment_df.dropna(subset=["topic_id"]).copy()
posts_with_topics["topic_id"] = posts_with_topics["topic_id"].astype(int)

# 8) build fixed order table
stats = posts_with_topics.groupby("topic_id")["compound"].agg(["mean", "std", "count"]).round(4).reset_index()
stats = stats.rename(columns={"mean": "mean_sentiment", "std": "std_sentiment", "count": "post_count"})
stats["topic_num"] = stats["topic_id"] + 1
stats["label"] = stats["topic_id"].map(labels_map)
stats = stats.sort_values("topic_num")

print("\n" + "=" * 80)
print("TABLE A: FIXED ORDER (Topic 1..N as in Exercise 4.1)")
print("=" * 80)
print(f"{'Topic':<7} {'Label':<35} {'Avg Sentiment':<15} {'Std Dev':<12} {'Posts':<8} {'Tone'}")
print("-" * 100)
for _, r in stats.iterrows():
    avg = r["mean_sentiment"]
    tone_row = "Positive" if avg >= 0.05 else ("Negative" if avg <= -0.05 else "Neutral")
    print(f"{int(r['topic_num']):<7} {str(r['label'])[:33]:<35} {avg:>+7.4f}        {r['std_sentiment']:>7.4f}     {int(r['post_count']):<8} {tone_row}")

# 9) sorted by positivity
sorted_stats = stats.sort_values("mean_sentiment", ascending=False).reset_index(drop=True)

print("\n" + "=" * 80)
print("TABLE B: SORTED BY POSITIVITY (Highest to Lowest)")
print("=" * 80)
print(f"{'Rank':<5} {'Topic':<7} {'Label':<35} {'Avg Sentiment':<15} {'Std Dev':<12} {'Posts':<8} {'Tone'}")
print("-" * 100)
for i, r in sorted_stats.iterrows():
    avg = r["mean_sentiment"]
    tone_row = "Positive" if avg >= 0.05 else ("Negative" if avg <= -0.05 else "Neutral")
    print(f"{i+1:<5} {int(r['topic_num']):<7} {str(r['label'])[:33]:<35} {avg:>+7.4f}        {r['std_sentiment']:>7.4f}     {int(r['post_count']):<8} {tone_row}")

# 10) findings
most_pos = sorted_stats.iloc[0] if not sorted_stats.empty else None
most_neg = sorted_stats.iloc[-1] if not sorted_stats.empty else None

print("\n" + "=" * 80)
print("KEY FINDINGS")
print("=" * 80)
if most_pos is not None and most_neg is not None:
    print(f"Most positive topic: Topic {int(most_pos['topic_num'])} - {most_pos['label']}")
    print(f"  Average sentiment: {most_pos['mean_sentiment']:+.4f}  based on {int(most_pos['post_count'])} posts")
    print(f"Most negative topic: Topic {int(most_neg['topic_num'])} - {most_neg['label']}")
    print(f"  Average sentiment: {most_neg['mean_sentiment']:+.4f}  based on {int(most_neg['post_count'])} posts")
    spread = float(most_pos["mean_sentiment"] - most_neg["mean_sentiment"])
    print(f"\nSentiment spread across topics: {spread:.4f}")
    if spread > 0.30:
        print("Topics show significant sentiment variation.")
    elif spread > 0.15:
        print("Topics show moderate sentiment variation.")
    else:
        print("Topics have similar sentiment levels.")
else:
    print("Not enough data to compute findings.")


# 12) summary line for easy copy to report
print("\n" + "=" * 80)
print("SUMMARY FOR REPORT")
print("=" * 80)
print(f"Overall sentiment: {overall_mean:+.4f} ({tone})")
print("Done.")
