import pandas as pd

def load_traffic_data(file_path):
    # reading CSV file
    df = pd.read_csv(file_path)

    # converting timestamp to proper datetime format
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    return df