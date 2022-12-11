import os
import pandas as pd
import csv


class Extract:
    def __init__(self, path='data') -> None:
        self.path = path
        self.check_files()

    def check_files(self):
        self.file_names = os.listdir(self.path)
        return self.file_names

    # def csv_files_(self):
    #     self.csv_files = list(filter(lambda x: x.split('.')[
    #                           1] == 'csv', self.file_names))
    #     return self.csv_files

    def csv_file_name(self, file):
        file = file.split('.')[0]
        return file

    def reading_csv_files(self, file):
        read = pd.read_csv(f'{self.path}/{file}')
        return read

    def df_arrange(self, df, file):
        df['name'] = self.csv_file_name(file)
        df.columns = ['date', 'low', 'open', 'volume',
                      'high', 'close', 'adjustedClose', 'name']
        df = df[['name', 'date', 'low', 'open',
                 'volume', 'high', 'close', 'adjustedClose']]
        df['date'] = pd.to_datetime(df['date'], dayfirst=True)
        df['date'] = [d.strftime(
            '%m-%d-%Y') if not pd.isnull(d) else '' for d in df['date']]
        return df

    def delete_file(self, file):
        os.remove(f'{self.path}/{file}')

    def download_csv_nasdaq(self, data):
        cols = ['date', 'low', 'open', 'volume',
                'high', 'close', 'adjustedClose']
        result = [{col: getattr(d, col) for col in cols} for d in data]
        result = pd.DataFrame.from_dict(
            pd.json_normalize(result)).to_csv(index=False)
        return result

    def get_nasdaq_data(self, data):
        cols = ['id', 'date', 'low', 'open', 'volume',
                'high', 'close', 'adjustedClose']
        result = [{col: getattr(d, col) for col in cols} for d in data]
        return result
