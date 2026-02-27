
import json
import os
import traceback
from datetime import datetime, timezone
from pymongo import MongoClient

OUT = {
    "question": "Most liked social media post before Antonio Nariño death bicentenary (2023-12-13)"
}

def ser(v):
    t = type(v).__name__
    if t == "ObjectId":
        return str(v)
    if isinstance(v, datetime):
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc).isoformat()
        return v.isoformat()
    if isinstance(v, list):
        return [ser(x) for x in v]
    if isinstance(v, dict):
        return {str(k): ser(vv) for k, vv in v.items()}
    return v

client = None
try:
    client = MongoClient(
        os.environ["MONGO_URI"],
        serverSelectionTimeoutMS=20000,
        connectTimeoutMS=20000,
        socketTimeoutMS=20000,
    )
    OUT["ping"] = client.admin.command("ping")
    cutoff = datetime(2023, 12, 13, tzinfo=timezone.utc)
    col = client["video_game_store"]["Social Media"]
    filt = {"Date": {"$lt": cutoff}}
    OUT["cutoff"] = cutoff.isoformat()
    OUT["matching_count"] = col.count_documents(filt)
    docs = list(col.find(filt).sort([("Likes", -1), ("Date", 1), ("Post ID", 1)]).limit(10))
    OUT["top10"] = [ser(x) for x in docs]
    if docs:
        d = docs[0]
        OUT["answer"] = {
            "post_id": d.get("Post ID"),
            "date": ser(d.get("Date")),
            "social_media_platform": d.get("Social Media Platform"),
            "post_type": d.get("Post Type"),
            "likes": d.get("Likes"),
            "comments": d.get("Comments"),
            "shares": d.get("Shares"),
            "views": d.get("Views"),
        }
    else:
        OUT["answer"] = None
except Exception as e:
    OUT["error"] = str(e)
    OUT["traceback"] = traceback.format_exc()
finally:
    try:
        if client is not None:
            client.close()
    except Exception:
        pass
    with open("social_media_top_post_result.json", "w", encoding="utf-8") as f:
        json.dump(OUT, f, indent=2, default=ser)
    print(json.dumps(OUT, indent=2, default=ser))
