import pandas as pd
# Importing required libraries
import joblib


urls_data = pd.read_csv(".\ml_ids\mail_url_dataset.csv")
urls_data.head()

def makeTokens(f):
    tkns_BySlash = str(f.encode('utf-8')).split('/') # make tokens after splitting by slash
    total_Tokens = []

    for i in tkns_BySlash:
            tokens = str(i).split('-') # make tokens after splitting by dash
            tkns_ByDot = []

    for j in range(0,len(tokens)):
        temp_Tokens = str(tokens[j]).split('.') # make tokens after splitting by dot
        tkns_ByDot = tkns_ByDot + temp_Tokens
        total_Tokens = total_Tokens + tokens + tkns_ByDot
        total_Tokens = list(set(total_Tokens))  #remove redundant tokens

        if 'com' in total_Tokens:
            total_Tokens.remove('com') # removing .com since it occurs a lot of times and it should not be included in our features
    
    return total_Tokens

url_list = urls_data["url"]
y = urls_data["label"]

from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer

vectorizer = TfidfVectorizer(tokenizer=makeTokens)

X = vectorizer.fit_transform(url_list)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)   
logit = LogisticRegression()
logit.fit(X_train, y_train)

print("Accuracy ",logit.score(X_test, y_test))

X_predict = ["https://www.section.io/engineering-education/",
"https://www.youtube.com/",
"https://www.traversymedia.com/", 
"https://www.kleinehundezuhause.com", 
"http://ttps://www.mecymiafinance.com",
"https://www.atlanticoceanicoilandgas.com"]

X_predict = vectorizer.transform(X_predict)
New_predict = logit.predict(X_predict)

print(New_predict)

X_predict1 = ["http://www.garage-pirenne.be/index.php?option=com_content&view=article&id=70&vsig70_0=15"]


X_predict1 = vectorizer.transform(X_predict1)
New_predict1 = logit.predict(X_predict1)
print(New_predict1)


# Saving the trained model as a file
joblib.dump(logit, 'model.pkl')

# predict for me
def predict_for_me(url):
    X_predict1 = [url]

    load = joblib.load('model.pkl')
    X_predict1 = vectorizer.transform(X_predict1)
    print(load.predict(X_predict1))

predict_for_me('https://www.youtube.com/watch?v=WZl5-JhJh}')