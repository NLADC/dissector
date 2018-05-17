import pymongo


def mongodb_insert(obj):
    """
    Inserts a object into MongoDB. Please change the host if necessary.
    :param obj: The object to insert
    :return: None
    """
    client = pymongo.MongoClient(host="127.0.0.1", port=27017)

    database = client.get_database("ddosdb")
    database.authenticate("ddosdb", "PASSWORD")

    collection = database.get_collection("ddosdb")

    collection.insert_one(obj)
