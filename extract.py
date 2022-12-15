import os
import pandas as pd
import csv
from flask import make_response


class Extract:
    def __init__(self, path='uploads') -> None:
        self.path = path
        self.check_files()

    def check_files(self):
        self.file_names = os.listdir(self.path)
        return self.file_names

    def csv_file_name(self, file):
        file = file.split('.')[0]
        return file

    def reading_csv_files(self, file):
        read = pd.read_csv(f'{self.path}/{file}')
        return read

    def reading_json_files(self, file):
        read = pd.read_json(f'{self.path}/{file}')
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

    def download_json_nasdaq(self, data):
        cols = ['date', 'low', 'open', 'volume',
                'high', 'close', 'adjustedClose']
        result = [{col: getattr(d, col) for col in cols} for d in data]
        result = {'results': result}

        return result

    def get_nasdaq_data(self, data):
        cols = ['id', 'date', 'low', 'open', 'volume',
                'high', 'close', 'adjustedClose']
        result = [{col: getattr(d, col) for col in cols} for d in data]
        return result

    def file_download(self, fileName, data, fileType):
        response = make_response(data)
        cd = 'attachment; filename='+fileName+'.' + fileType
        response.headers['Content-Disposition'] = cd
        response.mimetype = 'text/'+fileType
        return response

    def file_type(self, file):
        fileType = file.split('.')[1]
        if fileType == 'csv':
            return self.reading_csv_files(file)
        elif fileType == 'json':
            return self.reading_json_files(file)
