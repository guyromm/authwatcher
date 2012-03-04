#!/usr/bin/python

#this file would typically go into /usr/local/bin

import re,json
import time,datetime,sys

conf = json.loads(open('/etc/authwatcher.json','r').read())
recipients = conf['recipients']

tcnt=0

def follow(thefile):
    global tcnt
    thefile.seek(0,2)      # Go to the end of the file
    while True:
         line = thefile.readline()
         if not line:
             time.sleep(0.1)    # Sleep briefly
             tcnt+=1
             if tcnt>=(3600*10): sys.exit(0) #make upstart restart me, just in case i'm following a rotated file
             continue
         yield line

logfile = open("/var/log/auth.log")
loglre = re.compile('^(?P<month>[^ ]+)( +)(?P<day>[^ ]+)( +)(?P<hour>[^ ]+)(\:+)(?P<minute>[^\:]+)(\:+)(?P<second>[^\: ]+)( +)(?P<hostname>[^ ]+)( +)(?P<pname>[\w]+)(\[(?P<pid>[\d]+)\]|)\: (?P<message>.*)$')
#Accepted publickey for www-data from 62.219.145.234 port 32159 ssh2
#reverse mapping checking getaddrinfo for bzq-219-145-234.static.bezeqint.net [62.219.145.234] failed - POSSIBLE BREAK-IN ATTEMPT!
msgres = ['error: channel_setup_fwd_listener: cannot listen to port\: (?P<lport_cannotlisten>[\d]+)'
          ,'subsystem request for (?P<name_subsystemerror>sftp)'
          ,'error: bind: Address already in use'
          ,'reverse mapping checking getaddrinfo for (?P<rhost_rmapfail>[^ ]+) \[(?P<raddr_rmapfail>[\d\.]+)\] failed - POSSIBLE BREAK-IN ATTEMPT\!'
          ,'PAM service\(sshd\) ignoring max retries(.*)'
          ,'PAM (?P<num_authfails>[\d]+) more authentication failure(s|); logname= uid=0 euid=0 tty=ssh ruser= rhost=(?P<raddr_authfails>[\w\d\.]+)  user=(?P<user_authfails>[\w]+)'
          ,'Address (?P<raddr_doesnotmap>[\d\.]+) maps to (?P<rhost_doesnotmap>[\-\w\.\d]+), but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!'
          ,'error: Bind to port (?P<port_bindfailed>[\d]+) on (?P<ip_bindfailed>[\d\.\:]+) failed: Address already in use.'
          ,'fatal: Cannot bind any address.'
          ,'Invalid user (?P<user_invaliduser>[\w\-]*) from (?P<raddr_invaliduser>[\d\.]+)'
          ,'pam_unix\(sshd:auth\): check pass; user unknown'
          ,'Received disconnect from (?P<rhost_disconnect>[\d\.]+): 11: (<?P<reason_disconnect>disconnected by user|Closed due to user request\.)'
          ,'Received disconnect from (?P<rhost_userdisconnect>[\d\.]+): 11: disconnected by user'
          ,'pam_unix\(sshd:auth\): authentication failure; logname= uid=(?P<uid_failauth>[\d]+) euid=(?P<euid_failauth>[\d]+) tty=ssh ruser= rhost=(?P<raddr_failauth>[\w\d\.]+) ( user=(?P<user_failauth>[\w]+)|)'
          ,'Failed (?P<failedwhat_failpw>[\w]+) for(?P<isinvalid_failpw> invalid user|) (?P<user_failpw>[\w\-]+) from (?P<raddr_failpw>[\d\.]+) port (?P<rport_failpw>[\d]+) ssh2'
          ,'error: connect_to (.*) port (.*): failed.'
          ,'last message repeated (\d+) times'
          ,'Accepted (?P<authtype_acceptkey>[\w]+) for (?P<user_acceptkey>[\w\-]+) from (?P<raddr_acceptkey>[\d\.]+) port (?P<rport_acceptkey>[\d]+) ssh2|Did not receive identification string from (?P<raddr_loginout>[\d\.]+)'
          ,'pam_unix\(sshd:session\): session (?P<action_loginout>opened|closed) for user (?P<user_loginout>[\w\-]+)( by \(uid=(?P<uid_loginout>[\d]+)\)|)']

shre = re.compile('('+'|'.join(msgres)+')$')
sudore = re.compile('(?P<user>[\w\-]+) : TTY=(?P<tty>[^ ]+) ; PWD=(?P<pwd>[^ ]+) ; USER=(?P<sudouser>[\w\-]+) ; COMMAND=(?P<cmd>.+)$')

y = datetime.datetime.now().year
months = {1:'Jan',2:'Feb',3:'Mar',4:'Apr',5:'May',6:'Jun',7:'Jul',8:'Aug',9:'Sep',10:'Oct',11:'Nov',12:'Dec'}
months2 = dict([(v, k) for (k, v) in months.iteritems()])
procs={} ; sshs={} ; accepts = {} ; loginouts = {} ; ssh_details=[]
failcnt=0 ; goodcnt=0 ; valueskip=0; domail=0
def failact(line,res):
    global failcnt,goodcnt
    if not res:
        print 'BAD PARSE:%s'%line
        failcnt+=1
        if failcnt>=10: raise Exception('too many failures (%s/%s)'%(failcnt,goodcnt))

import smtplib
from email.mime.text import MIMEText

myhost=None
earliest=None ; latest=None
def parseline(line,mail=False):
    global procs,sshs,failcnt,goodcnt,valueskip,domail,myhost,earliest,latest
    res = loglre.search(line)
    failact(line,res)
    if not res: 
        return None

    stamp = datetime.datetime(y,months2[res.group('month')],int(res.group('day')),int(res.group('hour')),int(res.group('minute')),int(res.group('second')))
    if not earliest or stamp<earliest: earliest = stamp
    if not latest or stamp>latest: latest= stamp
    myhost = host = conf.get('hostname',res.group('hostname'))
    pname = res.group('pname')
    msg = res.group('message')
    if pname not in procs: procs[pname]=0
    procs[pname]+=1
    goodcnt+=1
    if pname=='sshd':
        shres = shre.search(msg)
        if shres:
            gd = shres.groupdict()
            mk=None
            data={}
            for k,v in gd.items():
                if v!=None:
                    fp,mk = k.split('_')
                    data[fp]=v
                    if mk not in sshs: sshs[mk]=0
                    sshs[mk]+=1
            data['stamp']=stamp
            data['tp']=mk
            ssh_details.append(data)
            if mk in conf['ssh_alertkeys']:
                nomail=False
                for dk,dv in data.items():
                    if dk in conf['ssh_alertfields_not'] and re.compile(conf['ssh_alertfields_not'][dk]).search(dv):
                        #skip this alert
                        nomail=True
                        valueskip+=1
                        break
                
                if mail and not nomail:
                    domail+=1
                    me = conf.get('mx_sender','authmon@%s'%host)
                    print 'sending out emails to %s through %s as %s - %s'%(recipients,conf['mx'],me,line.strip())
                    for rcpt in recipients:
                        mymail = MIMEText(line)
                        mymail['Subject'] = '%s - %s'%(host,mk)+(data.get('user') and ': '+data.get('user') or '')+(data.get('raddr') and '@'+data.get('raddr') or '')
                        
                        you = rcpt
                        mymail['From'] = me
                        mymail['To']=you
                        s = smtplib.SMTP(conf['mx'])
                        if conf.get('mx_user'): s.login(conf.get('mx_user'),conf.get('mx_password'))
                        s.sendmail(me,[you],mymail.as_string())
                        s.quit()
                #print line.strip()
            #print 'session %s for %s by %s'%(act,user,uid) 
        else:
            failact(line.strip(),shres)
    elif pname=='sudo':
        sudores = sudore.search(msg)
        if sudores:
            u = sudores.group('user')
        else:
            failact(line.strip(),sudores)

def displist(l,title):
    op=''
    items = l.items()
    def ordf(a1,a2):
        return cmp(a1[1],a2[1])
    items.sort(ordf,reverse=True)
    op+= '======= %s ======\n'%title
    for i in items:
        op+= '%s\t\t%s\n'%i
    return op

if len(sys.argv)>1 and sys.argv[1]=='parseall':
    for line in logfile:
        parseline(line)

    print 'parsed %s. %s fails. %s value skips on alert. %s domails'%(goodcnt,failcnt,valueskip,domail)
    print displist(procs,'Processes')
    print displist(sshs,'SSH items')
elif len(sys.argv)>1 and sys.argv[1] in ['digest','testdigest','alltimedigest','testalltimedigest']:
    #we seek 10,000 bytes before file's end
    if 'alltime' not in sys.argv[1]:
        mydate = (datetime.datetime.now()-datetime.timedelta(days=1)).date()
        denom = -100000000 ; goodjump=False
        if False:
            while True:
                try:
                    logfile.seek(denom,2)
                    goodjump=True
                except:
                    print 'failed jump by %s'%denom
                    denom/=10
                if goodjump: break
            while True: 
                op = logfile.read(1)
                if op=='\n': break
            print'seeked backwards %s (by %s)'%(logfile.tell(),denom)
    lcnt=0
    for line in logfile:
        lcnt+=1
        parseline(line)
    pop= 'covered %s lines. %s - %s\n'%(lcnt,earliest,latest)
    procsop= displist(procs,'Processes')
    sshop= displist(sshs,'SSH')
    if 'alltime' not in sys.argv[1]: ssh_details = [det for det in ssh_details if det['stamp'].date()==mydate]
    def sshdetsort(s1,s2):
        cm = cmp('user' in s1 and s1['user'] or 'None','user' in s2 and s2['user'] or 'None')
        if (cm==0): cm = cmp(s1['stamp'],s2['stamp'])
        return cm
    ssh_details.sort(sshdetsort)
    def showlist(det):
        users={}
        mop=''
        for det in ssh_details:
            if 'user' in det:
                if det['user'] not in users: users[det['user']]={'user':det['user'],'times':0,'first':None,'last':None,'tps':[],'rhosts':[],'raddrs':[]}
                users[det['user']]['times']+=1
                if not users[det['user']]['first'] or det['stamp']<users[det['user']]['first']: users[det['user']]['first']=det['stamp']
                if not users[det['user']]['last'] or det['stamp']>users[det['user']]['last']: users[det['user']]['last']=det['stamp']
                for fn in ['tp','rhost','raddr']:
                    if fn in det\
                            and det[fn] not in users[det['user']][fn+'s']: 
                        users[det['user']][fn+'s'].append(det[fn])

            mop+='%s\t%s\t%s\n'%(det['stamp'],det['tp'],dict([(k,v) for k,v in det.items() if k not in ['stamp','tp']]))
        omp="users affected:\n%s\n\n"%("\n".join(["%s\t\t%s\t%s\t%s\t%s\t%s"%(u['user'],u['times'],u['first'],u['last'],','.join(sorted(u['tps'])),','.join(sorted(u['rhosts']+u['raddrs']))) for u in users.values()]))
        mop=pop+omp+mop+procsop+sshop
        return mop
    op = showlist(ssh_details)
    if sys.argv[1] in ['testalltimedigest','testdigest']: 
        print op
        sys.exit (0)
    me = conf.get('mx_sender','authmon@%s'%myhost)
    print 'sending out emails to %s through %s as %s - %s'%(recipients,conf['mx'],me,line.strip())
    for rcpt in recipients:
        mymail = MIMEText(op)
        if 'alltime' not in sys.argv[1]:
            mymail['Subject'] = 'digest %s for %s'%(myhost,mydate)
        else:
            mymail['Subject'] = 'digest %s for ALLTIME'%(myhost)
        you = rcpt
        mymail['From'] = me
        mymail['To']=you
        s = smtplib.SMTP(conf['mx'])
        if conf.get('mx_user'): s.login(conf.get('mx_user'),conf.get('mx_password'))
        s.sendmail(me,[you],mymail.as_string())
        s.quit()

else:
    #print '%s.%s'%(pname,stamp)
    loglines = follow(logfile)
    for line in loglines:
        parseline(line,mail=True)
