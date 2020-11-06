import json
import xml.dom.minidom
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from random import random
from time import sleep
from xml.dom.minidom import parse, parseString
from xml.etree.ElementTree import ElementTree, fromstring
import time
import requests
from flask import (Flask, Response, copy_current_request_context, flash,
                   make_response, redirect, render_template, request, session,
                   url_for)
from flask_wtf import CSRFProtect
from jinja2 import Template
from netconf_client.connect import connect_ssh
from netconf_client.ncclient import Manager
import sqlite3
import forms
import threading
import pygal
app = Flask(__name__)
app.secret_key='my_secret_key'
csrf= CSRFProtect(app)
csv=''
@app.before_request
def make_session_permanent():
    session.permanent = True
    #app.permanent_session_lifetime = timedelta(minutes=20)

def db_connection():
    conn=None
    try:
        conn=sqlite3.connect('Statistics.sqlite')
    except sqlite3.Error as e:
        print(e)
    return conn

def tokens(srvr,usr,pswd):
    urlToken=""+srvr+"/tron/api/v1/tokens"
    payload = {'authType': 'password',
                'username': usr,
                'password': pswd,
                'tenant': 'master'}
                
    responseTkn = requests.request("POST",urlToken, data = payload, verify=False)
    if 'Invalid credentials' in responseTkn.text or 'Sorry, no page could be found at this address (404)' in responseTkn.text or responseTkn.status_code==401 or 'token' not in responseTkn.text:
        tkn='invalid'
        print(tkn)
    else:
        tkn=responseTkn.json()['token']
    return(tkn)

def snetconf(ip,pt):
    try:
        ip="10.181.36.233"
        pt='28'
        usr='diag'
        pswd='ciena123'
        start_time = time.time()
        sessio = connect_ssh(host=ip, port=830, username=usr, password=pswd)
        mgr = Manager(sessio, timeout=200)
        #ip="10.176.64.169"
        ststs=[]
        filt="""<filter xmlns:if="urn:ietf:params:xml:ns:yang:ietf-interfaces" type="subtree">
            <interfaces>
            <interface>
                <name>"""+pt+"""</name>
            </interface>
            </interfaces>
        </filter>"""
        response= (str(mgr.get(filter=filt).data_xml)).replace("'","")[1:]
        doc = xml.dom.minidom.parseString(response)
        new_inOctets =''.join(str( [int(x.firstChild.data) for x in doc.getElementsByTagName("in-octets")][0]))
        new_inErrors = ''.join(str( [int(x.firstChild.data) for x in doc.getElementsByTagName("in-errors")][0]))
        new_outOctets = ''.join(str( [int(x.firstChild.data) for x in doc.getElementsByTagName("out-octets")][0]))                   
        new_outErrors= ''.join(str( [int(x.firstChild.data) for x in doc.getElementsByTagName("out-errors")][0]))
        new_discards  =''.join(str( [int(x.firstChild.data) for x in doc.getElementsByTagName("in-discards-octets")])) 
        ststs=[new_inOctets,new_inErrors,new_outOctets,new_outErrors,new_discards.replace('[','').replace(']','')]
        print("--- %s seconds ---" % (time.time() - start_time))
        now = datetime.now()
        d_string = now.strftime("%Y-%m-%d %H:%M:%S")
        ststs=[new_inOctets,new_inErrors,new_outOctets,new_outErrors,new_discards.replace('[]','0'),d_string]
        sessio.close()
        return(ststs)
    except:
        ststs=[]
        return(ststs)

def task(srvr,usr,pswd):
    
    conn=db_connection()
    cursor=conn.cursor()
    while(srvr!=1):
        start_time = time.time()
        tkn=tokens(srvr,usr,pswd)
        device=""
        url = srvr+"/nsi/api/v1/search/networkConstructs?include=expectations%2CphysicalLocation&limit=200&networkConstructType=networkElement%2Cmanual&offset=0&resourcePartitionInfo=&searchFields=data.attributes.displayData.displayName%2Cdata.attributes.ipAddress%2Cdata.attributes.resourceType%2Cdata.attributes.displayData.displaySyncState%2Cdata.attributes.syncState.additionalText&resourceType="+device+"&sortBy=data.attributes.displayData.displayName&subnetName="
        payload = {}
        headers = {
        'Authorization': 'Bearer '+tkn+'',
        'Content-Type': 'application/json',
        }
        response = requests.request("GET", url, headers=headers, data = payload,verify=False)
        #print(response.text.encode('utf8'))
        res=response.json()
        for item in res['data']:
            try:
                new_NEId=str(item['id'])
                new_name=str(item['attributes']['displayData']['displayName'])
                new_ip=str(item['attributes']['displayData']['displayIpAddress'])
                sql="""INSERT INTO NEs (NEId,name,ip)
                        VALUES (?, ?, ?)"""
                cursor=cursor.execute(sql, (new_NEId, new_name, new_ip))
                conn.commit()
            except:
                continue
        cursor=conn.execute("select NEId,ip from NEs")
        NEIds=[(item[0],item[1]) for item in cursor.fetchall()]
            
        for row in NEIds:
            url = srvr+"/nsi/api/tpes?networkConstruct.id="+row[0]+"&structureType=PTP&content=detail&"\
            "fields=data.attributes.nativeName%2Cdata.attributes.displayAlias%2C"\
            "data.attributes.layerTerminations.additionalAttributes.operSpeed%2Cdata.attributes.layerTerminations.operationalState&limit=100"
            response = requests.request("GET", url, headers=headers, data = payload,verify=False)
            res=response.json()
            for i in res['data']:
                new_NEId=row[0]
                new_portId=str(i['id'])
                new_portNumber=int(i['attributes']['nativeName'])
                new_portName=str(i['attributes']['displayAlias'])
                try:
                    operState=str(i['attributes']['layerTerminations'][0]['operationalState'])
                except:
                    continue
                #srvr="10.183.49.128"
                pt=str(new_portNumber)
                #pt="1"
                statistics=snetconf(row[1],pt)
                if not statistics:
                    continue
                else:
                    #t_string=now.strftime('%H:%M:%S')
                    
                    #new_time=t_string
                    sql="""INSERT INTO Ports (NEId,portId,portNumber,portName,inOctets, inErrors, outOctets, outErrors,discards, date)
                            VALUES (?, ?, ?, ?, ?,?,?,?,?,?)"""
                    #statistics=[0,0,0,0,0]
                    cursor=cursor.execute(sql, (new_NEId, new_portId, new_portNumber,new_portName,statistics[0], statistics[1], statistics[2], statistics[3], statistics[4], statistics[5]))
                    conn.commit()
                    print("loaded "+row[1]+":Port "+str(new_portNumber))
        time.sleep(300-(time.time() - start_time))
@app.route("/FileCSV", methods=['POST'])
def FileCSV():
    today = datetime.now()
    CSVForm=forms.CSVForm(request.form)
    if request.method=='POST' and CSVForm.validate():
        if 'token' not in session:
            return redirect(url_for('login'))
        else:
            now=today.strftime("%m-%d-%Y %H-%M")
            return Response(csv,mimetype="text/csv",headers={"Content-disposition":"attachment; filename=STATISTICS "+now+".csv"})
    else:
        return(url_for('login'))
    
@app.route('/history/<string:portId>/', defaults={'drange': None},methods=['GET','POST'])
@app.route('/history/<string:portId>/<string:drange>/',methods=['GET','POST'])
def history(portId,drange=""):
    global csv
    if 'token' not in session:
        return redirect(url_for('login'))
    else:
        '''grapho = pygal.Line()
        grapho.title = 'Out Throughput'
        numbers=(0,5,10,15,20,25)
        grapho.x_labels = map(str, numbers)
        grapho.add('OUT OCTETS', [0, 16.6,   25,   31, 36.4, 45.5])
        grapho_data=grapho.render_data_uri()'''
        connection=db_connection()
        cursorh=connection.cursor()
        if drange is None or drange=="":
            sql="""SELECT * FROM  v_stats WHERE portId=? order by date desc """
            cursorh=connection.execute(sql,(portId,))
        else:
            drangefilt=drange.split(' - ')
            sql="""SELECT * FROM  v_stats WHERE portId=? and date between ? and ? order by date desc """
            cursorh=connection.execute(sql,(portId,drangefilt[0],drangefilt[1]))
            print(drange)
        #sql="""SELECT * FROM  v_stats WHERE portId=? order by date desc """
        stats=[
            dict(ne=row[1],ip=row[2],name=row[3],inOctets=row[5],inErrors=row[6],outOctets=row[7],outErrors=row[8],discards=row[9],time=row[10],idPort=row[11])
            for row in cursorh.fetchall()
        ]
        csv='NE NAME,IP,PORT NAME,IN OCTETS, IN ERRORS, OUT OCTETS, OUT ERRORS, DISCARDS, DATE, PORT ID'
        ino=[]
        otime=[]
        outo=[]
        for x in stats:
            csv+='\n'+x.get("ne")+','+x.get("ip")+','+x.get("name")+','+str(x.get("inOctets"))+','+str(x.get("inErrors"))+','+str(x.get("outOctets"))+','+str(x.get("outErrors"))+','+str(x.get("discards"))+','+x.get("time")+','+x.get("idPort")+''
            ino.append(int(x.get("inOctets")))
            outo.append(int(x.get("outOctets")))
            otime.append(x.get("time"))
        #stats=[(item) for item in cursorh.fetchall()]
        connection.commit()

        #otime=otime[:11]
        otime.reverse()
        #ino=ino[:11]
        ino.reverse()
        #outo=outo[:11]
        outo.reverse()
        i=1
        gino=[]
        gouto=[]
        if len(ino)>20:
            limitgraph=20
        else:
            limitgraph=len(ino)
        while (i<=limitgraph-1):
            d=datetime.strptime(otime[i],'%Y-%m-%d %H:%M:%S')-datetime.strptime(otime[i-1],'%Y-%m-%d %H:%M:%S')
            d=float(d.total_seconds())
            gin=((ino[i]-ino[i-1])*8)/d
            gou=((outo[i]-outo[i-1])*8)/d
            gouto.append(round(gou,2))
            gino.append(round(gin,2))
            i+=1
        print(gino)
        graph = pygal.Line(x_label_rotation=40)
        graph.title = 'Throughput'
        graph.x_labels = map(str,otime[1:limitgraph])
        graph.add('IN (bps)', gino)
        graph.add('OUT (bps)', gouto)
        graph_data=graph.render_data_uri()

        drange_form=forms.DRangeForm(request.form)
        if request.method=='POST' and drange_form.validate():
            datetimes=drange_form.datetimes.data
            return redirect(url_for('history', portId=portId, drange=datetimes))
            
        return render_template('history.html',graph_data=graph_data,tableA=stats,portId=portId)

@app.route('/stats/<string:name>/<string:neid>/<string:srvr>/<string:pt>')    #int has been used as a filter that only integer will be passed in the url otherwise it will give a 404 error
def PM(name,neid,srvr,pt):
    if 'token' not in session:
        return redirect(url_for('login'))
    else:
        statistics=snetconf(srvr,pt)
        if not statistics:
            error_message="Invalid credentials"
            flash(error_message)
            statistics=[0,0,0,0,0]
        else:
            pass
    return render_template('template.html',title="Statistics",logout="Logout",in_octets= str(statistics[0]), in_errors= str(statistics[1]),
                                            out_octets= str(statistics[2]),out_errors= str(statistics[3]),in_discards_octets=str(statistics[4]), name=name, neid=neid, srvr=srvr,pt=pt)

@app.route('/',methods = ['POST', 'GET'])
def ne():
    if 'token' not in session:
        return redirect(url_for('login'))
    else:    
        neIds=[]
        scts=[]
        device=""
        url = session['server']+"/nsi/api/v1/search/networkConstructs?include=expectations%2CphysicalLocation&limit=200&networkConstructType=networkElement%2Cmanual&offset=0&resourcePartitionInfo=&searchFields=data.attributes.displayData.displayName%2Cdata.attributes.ipAddress%2Cdata.attributes.resourceType%2Cdata.attributes.displayData.displaySyncState%2Cdata.attributes.syncState.additionalText&resourceType="+device+"&sortBy=data.attributes.displayData.displayName&subnetName="
        payload = {}
        headers = {
        'Authorization': 'Bearer '+session['token']+'',
        'Content-Type': 'application/json',
        }
        response = requests.request("GET", url, headers=headers, data = payload,verify=False)
        res=response.json()
        try:
            for item in res['data']:
                name=str(item['attributes']['displayData']['displayName'])
                conectivity=str(item['attributes']['displayData']['displayAssociationState'])
                if conectivity=='Connected':
                    est='success'
                else:
                    est='danger'
                ip=str(item['attributes']['displayData']['displayIpAddress'])
                deviceType=str(item['attributes']['deviceType'])
                version=str(item['attributes']['softwareVersion'])
                scts.append([name,conectivity,ip,deviceType,version,est,item['id']])
                neIds.append(item['id'])
        except:
            session['token']=tokens(session['server'],session['username'],session['password'])
            return redirect(url_for('ne'))
        ports=[]
        for i in neIds:
            neId=i
            url = session['server']+"/nsi/api/tpes?networkConstruct.id="+neId+"&structureType=PTP&content=detail&"\
            "fields=data.attributes.nativeName%2Cdata.attributes.displayAlias%2C"\
            "data.attributes.layerTerminations.additionalAttributes.operSpeed%2Cdata.attributes.layerTerminations.operationalState&limit=100"
            response = requests.request("GET", url, headers=headers, data = payload,verify=False)

            #print(response.text.encode('utf8'))
            res=response.json()

            for item in res['data']:
                try:
                    portNumber=str(item['attributes']['nativeName'])
                    portName=str(item['attributes']['displayAlias'])
                    operState=str(item['attributes']['layerTerminations'][0]['operationalState'])
                    operSpeed=item['attributes']['layerTerminations'][1]['additionalAttributes']['operSpeed'].replace(" Bps",'')
                    operSpeed=str(int(int(operSpeed)*10**-9))+' Gbps'
                    portId=str(item['id'])
                    ports.append([neId,portNumber,portName,operState,operSpeed,portId])

                except:
                    continue
            #print(ports)
        return render_template('ne.html', title="Metrics",logout="Logout" , PRS=scts, PORTS=ports)


'''@app.route('/redirect/<string:red>/<string:pt>') 
def PM(red,pt):
    if 'token' not in session:
        return redirect(url_for('login'))
    else:       
        return render_template('redirect.html', title="Metrics",logout="Logout",red=red,pt=pt)'''

@app.route('/login',methods = ['GET','POST'])
def login():
    if 'token'  in session:
        return redirect(url_for('ne'))
    else:
        pass
    login_form=forms.LoginForm(request.form)
    if request.method=='POST' and login_form.validate():
        session['server']=login_form.server.data
        session['username']=login_form.username.data
        session['password']=login_form.password.data
        try:
            tkn=tokens(session['server'],session['username'],session['password'])
            print(tkn)
            if tkn=='invalid':
                error_message="Invalid credentials"
                flash(error_message)
            else:
                session['token']=tkn
                #task(session['server'],session['username'],session['password'])
                threading.Thread(target=task, args=(session['server'],session['username'],session['password'])).start()             
                return redirect(url_for('ne'))
                
        except requests.exceptions.HTTPError as errh:
            print ("Http Error:",errh)
            error_message="Invalid credentials"
            flash(error_message)
        except requests.exceptions.ConnectionError as errc:
            print ("Error Connecting:",errc)
            error_message="Invalid credentials"
            flash(error_message)
        except requests.exceptions.Timeout as errt:
            print ("Timeout Error:",errt)
            error_message="Invalid credentials"
            flash(error_message)
        except requests.exceptions.RequestException as err:
            print ("OOps: Something Else",err)
            error_message="Invalid credentials"
            flash(error_message)
            raise SystemExit(err)
    return render_template('login.html',title="login",form=login_form)


@app.route('/logout',methods=['GET','POST'])
def logout():
    if 'username' in session and 'server' in session and 'password' in session:
        session.pop('server')
        session.pop('username')
        session.pop('password')
    if 'token' in session:
        session.pop('token')
    return redirect(url_for('login'))

if __name__=='__main__':
    app.run(host="0.0.0.0",debug=True, port=4000)
