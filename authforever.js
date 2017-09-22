'use latest';

const AWS = require('aws-sdk');
const DOC = require('dynamodb-doc');
const AuthClient = require('auth0').AuthenticationClient;

var db = null;
var auth0 = null;
var secrets = {};

function findDomain(context){
    return new Promise((resolve, reject) => {

        db.getItem({
            TableName: context.secrets.USERS_TABLE,
            Key: { email: context.data.email }
        }, (err, result) => {

            if(err){
                reject(err);
            }else{

                if(result && result.Item){
                    resolve(result.Item);
                }else{
                    resolve(null);
                }

            }
        });
    });
}

function availableDomain(context){
    return new Promise((resolve, reject) => {

        db.scan({
            TableName: context.secrets.DOMAINS_TABLE,
            ScanFilter: [ db.Condition('numberOfUsers', 'LT', 7000) ]
        }, (err, result) => {
            if(err){
                reject(err);
            }else{
                resolve(result.Items[0]);
            }
        });

    });
}

function increaseUserCount(account){
    return new Promise((resolve, reject) => {

        db.updateItem({
            TableName: secrets.DOMAINS_TABLE,
            Key: { account: account },
            UpdateExpression: 'ADD #counter :incva',
            ConditionExpression: 'account = :account',
            ExpressionAttributeNames: {
                '#counter': 'numberOfUsers'
            },
            ExpressionAttributeValues: {
                ':incva': 1,
                ':account': account
            },
            ReturnValues:'UPDATED_NEW'
        }, (err, result) => {
            console.log(err);
            if(err){
                reject(err);
            }else{
                resolve(result);
            }
        });

    });
}

function createUser(data){
    return new Promise((resolve, reject) => {

        db.putItem({
            TableName: secrets.USERS_TABLE,
            Item: data
        }, (err, result) => {
            if (err) {
                reject(err);
            } else {
                resolve(result);
            }
        });

    });
}

function signup(data, credentials){

    data.connection = 'Username-Password-Authentication';
    return auth0.database.signUp(data).then(user => {
        if(user){
            return increaseUserCount(credentials.account).then(_ => {
                return createUser({ email: data.email, account: credentials.account, clientId: credentials.clientId });
            }).then(_ => {
                return user;
            });
        }
    });
}

function auth(data){

    return auth0.database.signIn({
        username: data.username,
        password: data.password,
        connection: 'Username-Password-Authentication',
        scope: data.scope || 'openid profile email'
    });
}

module.exports = (context, callback) => {

    AWS.config.update({
        accessKeyId: context.secrets.AWS_ACCESS_KEY_ID,
        secretAccessKey: context.secrets.AWS_SECRET_ACCESS_KEY,
        region: 'us-east-1'
    });

    db = new DOC.DynamoDB();
    docClient = new AWS.DynamoDB.DocumentClient();
    secrets = context.secrets;

    findDomain(context).then(userDomain => {

        if(userDomain){
            return userDomain;
        }else{
            return availableDomain(context);
        }

    }).then(credentials => {

        auth0 = new AuthClient({
            domain: `${ credentials.account }.auth0.com`,
            clientId: credentials.clientId
        });

        if(context.data.signup){
            return signup(context.data, credentials);
        }else{
            return auth(context.data);
        }

    }).then(data => {
        callback(data);
    }).catch(err => {
        callback(err.message);
    });

};
