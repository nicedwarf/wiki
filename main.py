import os
import webapp2
import jinja2
import json
import datetime
import re
from time import gmtime, strftime
import collections
import hashlib


from google.appengine.ext import db




template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = False)

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

### wiki stuff

class WikiHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))


def wiki_key(name = 'default'):
	return db.Key.from_path('wikis', name)


class Wiki(db.Model):
	wikiurl = db.StringProperty(required = True)
	wikicontent = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)



class Logout(WikiHandler):
    def get(self):
    	print "you found logout page"
        self.render('front.html')

class WikiPage(WikiHandler):


    def get(self, PAGE_RE):
	print "you found wiki page"
 	username_value = self.request.cookies.get('user')

        if username_value:

            val = username_value.split('|')[0]
            hash_cookie = hashlib.sha1(val).hexdigest()
            total_hash = "%s|%s" % (val, hash_cookie)
            if username_value == total_hash:
                print (val)
                print (username_value)    
               
                wikiurl = PAGE_RE
                wikis = db.GqlQuery("select * from Wiki where wikiurl =:1 order by created desc", wikiurl)
                wikipost = wikis.get()
                print wikipost
                if wikipost:
                	wikitext = wikipost.wikicontent
                	self.render('front.html',  PAGE_RE = PAGE_RE, wikitext = wikitext, username = val)
                else:
                	self.render('front.html', PAGE_RE = PAGE_RE, username = val)

        else:
        	wikiurl = PAGE_RE
        	wikis = db.GqlQuery("select * from Wiki where wikiurl =:1 order by created desc", wikiurl)
        	wikipost = wikis.get()
        	print wikipost
        	if wikipost:
        		wikitext = wikipost.wikicontent
        		self.render('frontloggedout.html',  PAGE_RE = PAGE_RE, wikitext = wikitext)
        	else:
        		self.render('frontloggedout.html', PAGE_RE = PAGE_RE)



class EditPage(WikiHandler):
    def get(self, PAGE_RE): 
    	print "you found edit page"
    	print PAGE_RE
    	wikiurl = PAGE_RE
    	wikis = db.GqlQuery("select * from Wiki where wikiurl =:1 order by created desc", wikiurl)
    	wikipost = wikis.get()
    	
        if wikipost:
        	wikitext = wikipost.wikicontent
        	self.render('edit.html',  PAGE_RE = PAGE_RE, wikitext = wikitext)
    	else:
    		print "no wiki found"
    		self.render('edit.html', PAGE_RE = PAGE_RE)
    	

    def post(self, PAGE_RE):
    	print "you are in the post handler"
    	wikicontent = self.request.get("wikicontent")
    	print PAGE_RE
    	if wikicontent:
    		print "you are posting a new wiki"
    		w = Wiki(parent = wiki_key(), wikiurl = PAGE_RE, wikicontent = wikicontent)
    		w.put()
    		c = str(w.key())
    		self.redirect(PAGE_RE)
    	else:
    		print PAGE_RE
    		self.redirect(PAGE_RE)






USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

def UserDB_key(name = 'default'):
    return db.Key.from_path('users', name)

class UserDB(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)





def make_secure_val(password):
    return "%s|%s" % (password, hash(password))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val



class Signup(WikiHandler):


    def get(self): 
        print "signup handler"
        


        username_value = self.request.cookies.get('user')

        if username_value:

            val = username_value.split('|')[0]
            
            hash_cookie = hashlib.sha1(val).hexdigest()

            total_hash = "%s|%s" % (val, hash_cookie)

            if username_value == total_hash:
                print (val)
                print (username_value)    
                self.redirect('/')

            else:
                print (val)
                print (username_value) 
                print "failed validation"
                self.render('front.html')
        
        else:
            self.render('signup.html')

    def post(self):
    	print "posting handler"
        have_error = False
    	username = self.request.get('username')
    	password = self.request.get('password')
    	verified_password = self.request.get('verified_password')
    	email = self.request.get('email')
        userok = db.GqlQuery("SELECT * FROM UserDB WHERE username =:1", username)
        results = userok.get()

    	params = dict(username = username, email = email)

    	if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if results:
            usernameDB = results.username
            print (usernameDB)
            passwordDB = results.password
            print (passwordDB)
            if usernameDB and passwordDB == password:
                #print ("user exists")
                    #params['error_username'] = "That's not a valid username."
                    #self.render('front.html')
                params['error_username'] = "That user already exists."
                have_error = True
            else:
            	print "now what"

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True

        elif password != verified_password:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

    	if have_error:
            self.render('front.html', **params)
        
        else:
           
            #usernameDB = results.username
            #print (usernameDB)
            #passwordDB = results.password
            #print (passwordDB)


            #if usernameDB and passwordDB == password:
                #print ("user exists")
                    #params['error_username'] = "That's not a valid username."
                   # self.render('front.html')

         
            self.response.headers['Content-Type'] = 'text/plain'
            utf8username = username.encode("utf-8")

            cookie_hash = hashlib.sha1(username).hexdigest()

            self.response.headers.add_header('Set-Cookie', 'user= %s|%s' % (utf8username, cookie_hash))
            print PAGE_RE
            self.redirect('/')
            b = UserDB(parent = UserDB_key(), username = username, password = password)
            b.put()
            

class Logout(WikiHandler):

    def get(self):
        print "logging out"
        self.response.delete_cookie('user')
        self.redirect('/')

class Login(WikiHandler):
    
    def get(self):
        print "you made it to login"
        username_value = self.request.cookies.get('user')

        if username_value:

            val = username_value.split('|')[0]
            
            hash_cookie = hashlib.sha1(val).hexdigest()

            total_hash = "%s|%s" % (val, hash_cookie)

            if username_value == total_hash:
                print (val)
                print (username_value)    
                self.redirect('/')

            else:
                print (val)
                print (username_value) 
                print "failed validation"
                self.render('login.html')
        
        else:
            self.render('login.html')


    def post(self):
    	print "posting handler"
        have_error = False
    	username = self.request.get('username')
    	password = self.request.get('password')
    	verified_password = self.request.get('verified_password')
    	email = self.request.get('email')
        userok = db.GqlQuery("SELECT * FROM UserDB WHERE username =:1", username)
        results = userok.get()
        

    	params = dict(username = username, email = email)

    	#if not valid_username(username):
        #    params['error_username'] = "That's not a valid username."
        #   have_error = True

        if results:
            
            usernameDB = results.username
            
            passwordDB = results.password
            
            if usernameDB and passwordDB == password:
                
                self.response.headers['Content-Type'] = 'text/plain'
                utf8username = username.encode("utf-8")
                cookie_hash = hashlib.sha1(username).hexdigest()
                self.response.headers.add_header('Set-Cookie', 'user= %s|%s' % (utf8username, cookie_hash))
                
                self.redirect('/')
                
            else:
            	self.redirect('signup')

    
        
        else:
            self.redirect('signup')
         

            


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage),
                               ],
                              debug=True)