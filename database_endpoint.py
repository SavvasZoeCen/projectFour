from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine, select, MetaData, Table
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only

from models import Base, Order, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

#These decorators allow you to use g.session to access the database inside the request code
@app.before_request
def create_session():
    print(">>>create_session")
    g.session = scoped_session(DBSession) #g is an "application global" https://flask.palletsprojects.com/en/1.1.x/api/#application-globals
    print("create_session>>>")

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    print(">>>shutdown_session")
    g.session.commit()
    g.session.remove()
    print(">>>shutdown_session")

"""
-------- Helper methods (feel free to add your own!) -------
"""

def log_message(d):
    # Takes input dictionary d and writes it to the Log table
    print(">>>log_message")
    msg = json.dumps(d)
    log = Log(message = msg)
    g.session.add(log)
    g.session.commit()
    print("log_message>>>")

"""
---------------- Endpoints ----------------
"""
    
@app.route('/trade', methods=['POST'])
def trade():
    print(">>>trade")
    if request.method == "POST":
        content = request.get_json(silent=True)
        print( ">>>>>>>>>>>>>>>>>>>>>", f"content = {json.dumps(content)}" )
        columns = [ "sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform" ]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            log_message(content)
            return jsonify( False )
            
        #Your code here
        #Note that you can access the database session using g.session
        sig = content['sig']
        payload_pk = content['payload']['sender_pk']
        payload = json.dumps(content['payload'])
        #verify the payload using the sender_pk.
        if c['platform'] == 'Algorand':
            ver = algosdk.util.verify_bytes(payload.encode('utf-8'), sig, payload_pk)
        elif content['payload']['platform'] == 'Ethereum':
            eth_encoded_msg = eth_account.messages.encode_defunct(text=payload)
            ver = eth_account.Account.recover_message(eth_encoded_msg,signature=sig) == payload_pk
        else:
            print('"platform" field must be either "Algorand" or "Ethereum"')
            log_message(content)
            return jsonify( False )
            
        #If the signature verifies, store the signature, as well as all of the fields under the ‘payload’ in the “Order” table EXCEPT for 'platform'.
        if ver:
            del content['payload']['platform']
            content['payload']['sig'] = sig
            order = Order(**{f:content['payload'][f] for f in content['payload']})
            g.session.add(order)
            g.session.commit()
            return jsonify( True )
        
        #If the signature does not verify, do not insert the order into the “Order” table. Instead, insert a record into the “Log” table, with the message field set to be json.dumps(payload).
        else:
            print('signature does not verify')
            log_message(payload)
            return jsonify( False )

@app.route('/order_book')
def order_book():
    #Your code here
    #Note that you can access the database session using g.session
    print(">>>order_book")
    orders = g.session.query(Order).options(laod_only("sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature")).all()
    print("~~~~~~~~~~~~~", orders)
    result = {'data': orders}
    print(">>>order_book")
    return jsonify(result)

if __name__ == '__main__':
    app.run(port='5002')
