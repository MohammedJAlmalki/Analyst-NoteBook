import sqlite3
import sys
import csv
import json
import requests
from shodan import Shodan
import configparser,os
from time import sleep
import time


dbconnection = sqlite3.connect("AnalystNB.db")
cursor = dbconnection.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS maindb (Date Date,IP TEXT,Country TEXT,ASN TEXT, ORGName TEXT,Hostnames TEXT,Ports TEXT,Source TEXT)")
cursor.execute("CREATE TABLE IF NOT EXISTS history (Date Date,IP TEXT,Casename TEXT,Note TEXT, number INTEGER)")
config = configparser.ConfigParser()
path=os.path.abspath(os.getcwd())
config.read(os.path.join(path, 'config.ini'))
access_token = config['config']['shodan_token']
access_token=access_token.strip('"')
api = Shodan(access_token)
if access_token=='':
    print("Error:Enter Shodan Token in \"config.ini\"\n Refer to Help for more information")
    pass
else:
    pass
keep_running='c'
banner= """

                        
                         ,.          .         .     .  .     .       ,-.          ,   
                        /  \         |         |     |\ |     |       |  )         |   
                        |--| ;-. ,-: | . . ,-. |-    | \| ,-. |-  ,-. |-<  ,-. ,-. | , 
                        |  | | | | | | | | `-. |     |  | | | |   |-' |  ) | | | | |<  
                        '  ' ' ' `-` ' `-| `-' `-'   '  ' `-' `-' `-' `-'  `-' `-' ' ` 
                                       `-'                                             
                                                                                                                                         
                                              Version 1.0                                                                                                                             
                                       By MohammedAlmalki@2020
                                   
   """




def start():
    print(banner)
    main ()

def help():
    print(""" 
    
                       Analyst NoteBook 
                       Version 1.0 
                       
    # AnalystNB supports the analysis mission of Adversaries Infrastructures with focus in simplicity and ease of use
    # Prequisites:
    - Python 3.0 
    # AnalystNB provides:
    - Database to enable queries and records storage
    - Automate IP information collection from multiple sources
    - Support bulk queries 
    - Enable Structured Case Oriented Investigations
    - Enriching queries with analyst's comments
    # Make sure to enter Shodan community API token into "config.ini"
    # Options are selectable using the corresponding numbers
    # For bulk queries , make sure to enter the IP list into the "in.csv" file in the form xxx.xxx.xxx.xxx with 
      no additions each in separate line
    # To show all database entries, leave the search input blank
    # Advance Search is SQL based search , following tables represents the Database tables Schema:
    # Table (1) : maindb
    
                                |---------------------------------------------------|
                                | Date|IP|Country|ASN|ORGName|Hostnames|Ports|Source|
                                |---------------------------------------------------|
    # Table (2) : history
    
                                                |---------------------|
                                                |Date|IP|Casename|Note|
                                                |---------------------|


    # For bugs, inquiries and ideas please let me know at mohammedjalmalki@outlook.sa :)
    
    """)

def history_list():
    history=cursor.execute("SELECT * FROM history").fetchall()
    print('\n\n\n\n|---------------------------------------------------------------------------------------')
    print('|   {:^3}   {:^10}   {:^15}   {:^15}  {:^30}'.format('ID','Date','IP Address','CaseName','Note'))

    for record in history:
        date=record[0]
        ip=record[1]
        case=record[2]
        note= record[3]
        number=record[4]
        print('|   {:^3}   {:^10}   {:^15}   {:^15}  {:^30}'.format(number,date,ip,case[:15],note[:30]))
    print('|--------------------------------------------------------------------------------|\n\n\n')


def dashboard():
  Total_Entry_Count=cursor.execute("SELECT count(IP) FROM maindb").fetchall()
  IP_count=Total_Entry_Count[0][0]
  if IP_count== 0:
      print("\t\t\t\t\tDatabase is empty!")
      main()
  else:
      pass
  Top_Repeated_Query=cursor.execute("SELECT IP,count(IP)as count FROM maindb group by IP order by count desc limit 3").fetchall()
  Top_Cases_IPs=cursor.execute("SELECT Casename,count(*) as count FROM history group by Casename order by count desc limit 3").fetchall()
  Top_Countries=cursor.execute("SELECT Country,count(*) as count FROM maindb group by Country order by count desc limit 3").fetchall()
  print('{:>75}'.format('=========Dashboard========='))
  print("{:>70}{:<25}\n".format("Total Queries Number:",Total_Entry_Count[0][0]))
  seperator='---------------------------------------------------'

  print(('{:^23}{:^15}{:^45}{:^12}{:^15}\n').format('Top Queries By Count','','Top Cases by Associated Infra.','','Top Countries By Count'))
  print(('|{:^16}|{:^6}|{:^15}|{:^16}|{:^25}|{:^15}|{:^8}|{:^6}|').format('Query','Count','','Case Name','Number of Associated IPs','','Country','Count'))
  print(('|{}|{:^15}|{}|{:^15}|{}|').format(seperator[:23],'',seperator[:42],'',seperator[:15]))
  k=0
  length=[]
  length.extend([len(Top_Countries),len(Top_Repeated_Query),len(Top_Cases_IPs)])
  var_length=min(length)
  while k < (var_length):

       Query=Top_Repeated_Query[k][0]
       Count=Top_Repeated_Query[k][1]
       CaseName=Top_Cases_IPs[k][0]
       IP_no=Top_Cases_IPs[k][1]
       Country=Top_Countries[k][0]
       Country_Count=Top_Countries[k][1]
       print(('|{:^16}|{:^6}|{:^15}|{:^16}|{:^25}|{:^15}|{:^8}|{:^6}|').format(Query,Count,'',CaseName,IP_no,'',Country,Country_Count))
       k=k+1
  print('\n')
  print(('{:^23}{:^16}{:^45}\n').format('Top ASNs By Count','','Top Org Name by Count'))
  print(('|{:^16}|{:^6}|{:^20}|{:^25}|{:^6}|').format('ASN','Count','','Org Name','Count','','Country','Count'))
  print(('|{}|{:^20}|{}|').format(seperator[:23],'',seperator[:32]))
  f=0

  Top_ASNs=cursor.execute("SELECT ASN,count(*)as count FROM maindb group by ASN order by count desc limit 3").fetchall()
  Top_Org=cursor.execute("SELECT ORGNAME,count(*)as count FROM maindb group by ORGNAME order by count desc limit 3").fetchall()
  while f < len(Top_ASNs):

       ASN=Top_ASNs[f][0]
       ASN_Count=Top_ASNs[f][1]
       Org=Top_Org[f][0]
       Org_Count=Top_Org[f][1]
       print(('|{:^16}|{:^6}|{:^20}|{:^25}|{:^6}|').format(ASN,ASN_Count,'',Org[:25],Org_Count))
       f=f+1
  print('\n')


def historyoptions():
 Ch=input('=========================\n(1)Show All Tracklist\n(2)Search \n(3)Back\n>')
 if Ch == '1':
     history_list()
 elif Ch == '2':
     history_search()
 elif Ch == '3':
     main()
 else:
     print('Error! .. Enter Option Number')
 while keep_running=='c':
     historyoptions()


def search_maindb():

 Variable=input('Search:')
 result=cursor.execute("SELECT * FROM maindb WHERE Date like ? OR IP like ? OR Country like ? OR ASN like ? OR ORGName like ? OR Ports like ?", ('%'+Variable+'%','%'+Variable+'%','%'+Variable+'%','%'+Variable+'%','%'+Variable+'%','%'+Variable+'%')).fetchall()
 print('\n-----------------------------------------------------------------------------------')

 for record in result:
        date=record[0]
        ip=record[1]
        Country=record[2]
        ASN= record[3]
        ORGName=record[4]
        Hostnames=record[5]
        Ports=record[6]
        Source=record[7]
        More_data=cursor.execute("SELECT Casename,Note FROM history WHERE IP = ?", [ip]).fetchall()
        CaseName=More_data[0][0]
        Note=More_data[0][1]
        print('Date:{:<10}\nIP:{:<16}\nCase Name:{:<30}\nDescription:{:<50}\nCountry:{:<15}\nASN:{:<25}\nOrganisation Name:{:<25}\nPorts:{:<25}\nHostname:{:<25}\nSource:{:<10}'.format(date,ip,CaseName[:30],Note[:50],Country[:15],ASN[:15],ORGName[:25],Ports[:25],Hostnames[:25],Source[:10]))
        print('----------------------------------------------------------------------------------')



def history_search():

 Variable=input('Search:')
 result=cursor.execute("SELECT * FROM history WHERE Date like ? OR IP like ? OR Note like ? OR CaseName like ?", ('%'+Variable+'%','%'+Variable+'%','%'+Variable+'%','%'+Variable+'%')).fetchall()
 print('\n\n\n\n|---------------------------------------------------------------------------------------')
 print('|   {:^3}   {:^10}   {:^15}   {:^15}  {:^30}'.format('ID','Date','IP Address','CaseName','Description'))

 for record in result:
        date=record[0]
        ip=record[1]
        case=record[2]
        note= record[3]
        number=record[4]
        print('|   {:^3}   {:^10}   {:^15}   {:^15}  {:^30}'.format(number,date,ip,case[:15],note[:30]))
 print('-----------------------------------------------------------------------------------\n\n\n')


def remover(text):
    text_str=str(text)
    text_str=text_str.replace('\'','')
    return text_str

def sql_search():
   try:
    print("SQL Based Search\nFor Search Help go to help section \nOr type (Q) to Quit")
    sql_input=input("Search:")
    if sql_input == "Q":
        main()
    else:
        result= cursor.execute(sql_input).fetchall()
        for i in result:
         print(*i, sep = " | ")
        sql_search()
   except Exception as e:
       print ("Error:",e)
       sql_search()

def idseq():
 sequence = cursor.execute("SELECT max(number) FROM history").fetchall()
 if sequence[0][0]==None:
  number=0
 else:
  number=sequence[0][0]
 return number

def time_string():
    named_tuple = time.localtime() # get struct_time
    time_string = time.strftime("%d/%m/%Y", named_tuple)
    return time_string

def single_query():
 try:
     print('Single Query:\n')
     IP=input('Enter IP Address:')
     casename=input('Case Name: ')
     note=input('Note: ')
     ipinfo = api.host(IP)
     json_parser=ipinfo
     ip=(json_parser ['ip_str'])
     country=(json_parser ['country_code'])
     org=(json_parser ['org'])
     hostname_temp=str(json_parser ['hostnames'])
     hostnames=hostname_temp.replace('\'','')
     asn=(json_parser ['asn'])
     ports=(json_parser ['ports'])
     print('------------------------------------------------------------------------------------------------------')
     print ('IP:',ip,'|  COUNTRY:',country,'|  ASN:',asn,'|  ORG:',org,'|  HOSTNAME:',hostnames,'|  PORTS:',ports)
     print('------------------------------------------------------------------------------------------------------')
     number=idseq()
     time=time_string()
     source='IPINFO'
     cursor.execute("INSERT INTO history VALUES ('{}','{}', '{}' ,'{}' ,'{}')".format(time,ip,casename,note,number+1))
     cursor.execute("INSERT INTO maindb VALUES ('{}','{}', '{}','{}' ,'{}' ,'{}','{}','{}')".format(time,ip,country,asn,org,hostnames,ports,source))
     dbconnection.commit()
     while keep_running=='c':
      main()
 except Exception as e:
    print('No info from shodan - Querying IPINFO')
    req='https://ipinfo.io/'+IP
    response = requests.get(req)
    r = str(response.content.decode("utf-8"))
    json_parser=json.loads(r)
    ip=(json_parser ['ip'])
    country=(json_parser ['country'])
    org_all=(json_parser ['org']).split(' ',1)
    asn=org_all[0]
    asn=remover(asn)
    org=org_all[1]
    org=remover(org)
    ports='-'
    hostnames='-'
    number=idseq()
    time=time_string()
    source='Shodan'
    cursor.execute("INSERT INTO history VALUES ('{}','{}', '{}' ,'{}' ,'{}')".format(time,ip,casename,note,number+1))
    cursor.execute("INSERT INTO maindb VALUES ('{}','{}', '{}','{}' ,'{}' ,'{}','{}','{}')".format(time,ip,country,asn,org,hostnames,ports,source))
    dbconnection.commit()
    print('------------------------------------------------------------------------------------------------------')
    print ('IP:',ip,'|  COUNTRY:',country,'|  ASN:',asn,'|  ORG:',org)
    print('------------------------------------------------------------------------------------------------------')

    while keep_running=='c':
     main()


def bulk_query():
 check=input('Have You Entered IP Addresses in "in.csv"? (Y/N)\n')
 casename=input('Case Name:')
 note=input('Enter Desciption for the IP list:')
 if check == 'N':
      print('Please Enter IP Addresses # each in seperate row # into "in.csv" and try again \n')
      sys.exit()
 if check == 'Y':
     IP_list=[]
     with open("in.csv","r")as reg_reader:
         reader=csv.reader(reg_reader)
         for line in reg_reader:
             line1=line.strip()
             IP_list.append(line1)
     error_list=[]
     error_list1=[]
     i=1
     e=0
     er=0
     output_choice=input("Would you like export results to CSV file(Y/N):")
     for ip in IP_list:


      try:
         sleep(0.5)

         ipinfo = api.host(ip)
         json_parser=ipinfo
         ip=(json_parser ['ip_str'])
         country=(json_parser ['country_code'])
         asn=(json_parser ['asn'])
         org=(json_parser ['org'])
         hostnames_temp=str(json_parser ['hostnames'])
         hostnames=hostnames_temp.replace('\'','')
         ports=(json_parser ['ports'])
         time=time_string()
         number=idseq()
         source='Shodan'
         cursor.execute("INSERT INTO history VALUES ('{}','{}', '{}' ,'{}' ,'{}')".format(time,ip,casename,note,number+1))
         cursor.execute("INSERT INTO maindb VALUES ('{}','{}', '{}','{}' ,'{}' ,'{}','{}','{}')".format(time,ip,country,asn,org,hostnames,ports,source))
         dbconnection.commit()
         print (i,ip,country,asn,org,hostnames,ports)
         i+=1
         if output_choice == "N":
             pass
         elif output_choice == "Y":


             with open('out.csv', 'a',newline='\n') as outfile:
                 fieldnames = ['IP','Country','ASN','Org','Hostname','ports']
                 writer=csv.DictWriter(outfile, fieldnames=fieldnames)
                 writer.writerow({'IP':ip,'Country':country,'ASN':asn,'Org':org,'Hostname':hostnames,'ports':ports})
         else:
             print("Y or N only!")
      except Exception as error:
         error_list.append(ip)
         e+=1

     print('{} IP Addresses have no information in Shodan'.format(e))
     con=input('Would You Like To Continoue With "IPINFO" (Y/N):\n')
     if con== 'Y':
         for ip in error_list:
             try:
                 req='https://ipinfo.io/'+ip
                 response = requests.get(req)
                 r = str(response.content.decode("utf-8"))
                 json_parser=json.loads(r)
                 ip=(json_parser ['ip'])
                 country=(json_parser ['country'])
                 org_all=(json_parser ['org']).split(' ',1)
                 asn=org_all[0]
                 asn=remover(asn)
                 org=org_all[1]
                 org=remover(org)
                 number=idseq()
                 ports='-'
                 hostnames='-'
                 source='IPINFO'
                 cursor.execute("INSERT INTO history VALUES ('{}','{}', '{}' ,'{}' ,'{}')".format(time,ip,casename,note,number+1))
                 cursor.execute("INSERT INTO maindb VALUES ('{}','{}', '{}','{}' ,'{}' ,'{}','{}','{}')".format(time,ip,country,asn,org,hostnames,ports,source))
                 dbconnection.commit()
                 print (i,ip,country,org,hostnames,ports)
                 i+=1

                 if output_choice == "N":
                     pass
                 elif output_choice == "Y":


                    with open('out.csv', 'a',newline='\n') as outfile:
                     fieldnames = ['IP','Country','Org']
                     writer=csv.DictWriter(outfile, fieldnames=fieldnames)
                     writer.writerow({'IP':ip,'Country':country,'Org':org})
             except Exception as error:
                 print('Error Found with the Entry:',ip)
                 error_list1.append(ip)
                 er+=1
                 continue

         if not error_list1:
             pass
         else:
             print('{} Errors Found'.format(er))
             for ip in error_list1:
                 print('Error:',ip )
         while keep_running=='c':
             main()

     elif con == 'N':
         pass
     else:
         print('(Y/N)')
 else:
  print('(Y/N)')
  bulk_query()


def main():

 try:
     Ch=input('\t\t\t\t    ****************************\n(1)Dashboard\n(2)Query\n(3)Bulk Query\n(4)Tracklist\n(5)Search\n(6)Advance Search\n(7)Help\n(8)Exit\n>')
     if Ch == '2':
         single_query()
     elif Ch == '3':
         bulk_query()
     elif Ch == '8':
         exit()
     elif Ch== '4':
         historyoptions()
     elif Ch== '5':
         search_maindb()
     elif Ch== '7':
         help()
     elif Ch=='1':
        dashboard()
     elif Ch=='6':
         sql_search()
     else:
         print('Error! .. Enter Option Number')
     while keep_running=='c':
                main()

 except Exception as e:
     print("Error!",e)

start()

