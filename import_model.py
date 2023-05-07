import joblib
from sklearn.feature_extraction.text import TfidfVectorizer

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

vectorizer = TfidfVectorizer(tokenizer=makeTokens)

# predict for me
def predict_for_me(url):
    X_predict1 = [url]

    load = joblib.load('.\ml_ids\model.pkl')
    X_predict1 = vectorizer.transform(X_predict1)
    print(load.predict(X_predict1))

X_predict = ["https://www.section.io/engineering-education/",
"https://www.youtube.com/",
"https://www.traversymedia.com/", 
"https://www.kleinehundezuhause.com", 
"http://ttps://www.mecymiafinance.com",
"https://www.atlanticoceanicoilandgas.com"]
X_predict = vectorizer.transform(X_predict)
# New_predict = logit.predict(X_predict)

X_predict1 = ["http://www.garage-pirenne.be/index.php?option=com_content&view=article&id=70&vsig70_0=15"]


X_predict1 = vectorizer.transform(X_predict1)
# New_predict1 = logit.predict(X_predict1)
# print(New_predict1)

predict_for_me('https://www.youtube.com/watch?v=WZl5-JhJh}')