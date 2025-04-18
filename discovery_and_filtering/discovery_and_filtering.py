import pandas as pd

def read_alexa_top_csv(filepath:str='top-1m.csv',min_rank=1,max_rank=100):
    df= pd.read_csv(filepath)
    return df['site'].to_list()[min_rank:max_rank]

if __name__ == "__main__":
    print(read_alexa_top_csv())

