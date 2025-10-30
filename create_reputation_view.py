import sqlite3

def create_reputation_view(database_path='database.sqlite'):
    sql = """
    DROP VIEW IF EXISTS user_reputation_view;

    /* Reputation over the last 60 days:
       - +2 per 'like' on your posts
       - +3 per unique commenter on your posts
       (Window based on the post's created_at, which is present in this schema.)
    */
    CREATE VIEW user_reputation_view AS
    WITH likes AS (
      SELECT p.user_id AS uid, COUNT(r.id) AS c
      FROM posts p
      JOIN reactions r ON r.post_id = p.id
      WHERE r.reaction_type = 'like'
        AND p.created_at >= datetime('now','-60 day')
      GROUP BY p.user_id
    ),
    uniq_commenters AS (
      SELECT p.user_id AS uid, COUNT(DISTINCT c.user_id) AS c
      FROM posts p
      JOIN comments c ON c.post_id = p.id
      WHERE p.created_at >= datetime('now','-60 day')
      GROUP BY p.user_id
    )
    SELECT
      u.id AS user_id,
      COALESCE(2 * likes.c, 0) + COALESCE(3 * uniq_commenters.c, 0) AS score
    FROM users u
    LEFT JOIN likes ON likes.uid = u.id
    LEFT JOIN uniq_commenters ON uniq_commenters.uid = u.id;
    """
    conn = None
    try:
        conn = sqlite3.connect(database_path)
        conn.executescript(sql)
        conn.commit()
        print("Success: user_reputation_view created successfully!")
    except sqlite3.Error as e:
        print(f"Error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    create_reputation_view()
