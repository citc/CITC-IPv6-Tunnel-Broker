#!/usr/bin/env python

 # Copyright (C) CITC, Communications and Information Technology Commission,
 # Kingdom of Saudi Arabia.
 #
 # Developed by CITC Tunnel Broker team, tunnelbroker@citc.gov.sa.
 #
 # This software is released to public domain under GNU General Public License
 # version 2, June 1991 or any later. Please see file 'LICENSE' in source code
 # repository root.

# -*- coding: utf-8 -*-

import os, datetime
import bjsonrpc

from datetime import timedelta

import tornado.httpserver
import tornado.ioloop
import tornado.web

from ddtbmanage.config import DDTBManageConfig
from ddtbmanage.forms import *
from ddtbmanage.util import PasswordGenerator
from formencode import Invalid, All
from hashstore.hashstoremanager import *

config = DDTBManageConfig()
hashStore = HashStore(configFile=config.admin.configfile)


def is_admin_class_type(user):
    if user in hashStore.listUsers():
        return True
    return False

def is_unprivileged_class_type(user):
    rpc = bjsonrpc.connect(host=config.ipc.rpcip, port=int(config.ipc.port))
    retval = (user in rpc.call.listUsers(config.ipc.apikey))
    rpc.close()

    return retval

class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie('user')

    def get_current_role(self, user):
        if self.get_secure_cookie('role') is not None:
            return self.get_secure_cookie('role')
        return 'none'

    def set_secure_cookie(self, name, value, **kwargs):
        expires = datetime.utcnow() + timedelta(minutes=10)
        self.set_cookie(name, self.create_signed_value(name, value),
                        expires=expires, **kwargs)

class MainHandler(BaseHandler):
    title = 'TB management console: user home'
    def get(self):
        if not self.current_user:
            self.redirect('/login')
            return

        user_role = self.get_current_role(self.current_user)
        if user_role == 'admin':
            self.redirect('/admin/')
            return
        elif user_role == 'unprivileged':
            userDict = { }
            login = self.current_user

            try:
                self.rpc = bjsonrpc.connect(host=config.ipc.rpcip, port=int(config.ipc.port))
                userDict = self.rpc.call.userDetails(config.ipc.apikey, login)
                self.rpc.close()
            except Exception, e:
                self.set_secure_cookie("message", 'Error fetching user info, contact system administrator')

            message = self.get_secure_cookie('message')
            self.clear_cookie('message')
            self.render('templates/userIndex.html', message=message, userDict=userDict,
                         doctype='xhtml-transitional', title=self.title)

        else:
            self.redirect('/login')

class LoginHandler(BaseHandler):
    title = 'TB management console: user login'

    def get(self):
        if self.current_user:
            self.redirect('/')
            return

        message = self.get_secure_cookie("message")
        self.clear_cookie('message')
        self.render('templates/allLogin.html', message=message, errors={ },
                     doctype='xhtml-transitional', title=self.title)

    def post(self):
        if self.current_user:
            self.redirect('/')
            return

        message = None
        argumentList = ['user', 'passwd']
        data = { }
        errors = { }
        for argument in argumentList:
            try:
                if self.get_argument(argument):
                    data[argument] = self.get_argument(argument)
                    pass
            except Exception:
                pass

        form = LoginForm()
        try:
            data = form.to_python(data)
            self.rpc = bjsonrpc.connect(host=config.ipc.rpcip, port=int(config.ipc.port))
            if self.rpc.call.checkLogin(config.ipc.apikey, base64.b64encode(data['user'].encode('utf-8')), base64.b64encode(data['passwd'].encode('utf-8'))):
                self.set_secure_cookie("user", data['user'])
                self.set_secure_cookie("role", 'unprivileged')
                self.set_secure_cookie("message", "User %s successfully logged in." % data['user'])
                self.redirect('/')
                self.rpc.close()
                return
            else:
                self.rpc.close()
            message = 'Invalid username and/or password'
        except Invalid, e:
            errors = e.unpack_errors()

        self.render('templates/allLogin.html', message=message, errors=errors,
                     doctype='xhtml-transitional', title=self.title)

class LogoffHandler(BaseHandler):
    def get(self):
        self.clear_all_cookies()
        self.redirect('/')
        return

class AdminLogoffHandler(BaseHandler):
    def get(self):
        self.clear_all_cookies()
        self.redirect('/admin/login')
        return

class UserPasswdChangeHandler(BaseHandler):
    title = 'TB management console: user password change'
    template = 'templates/userPasswdChange.html'

    def get(self):
        if not self.current_user:
            self.redirect('/login')
            return

        message = self.get_secure_cookie("message")
        self.clear_cookie('message')
        self.render(self.template, message=message, errors={ },
                     doctype='xhtml-transitional', title=self.title)

    def post(self):
        if not self.current_user:
            self.redirect('/login')
            return

        try:
            self.check_xsrf_cookie()
        except tornado.web.HTTPError, e:
            self.set_secure_cookie("message", "XSRF attempted.")
            message = self.get_secure_cookie("message")
            self.render(self.template, message=message, errors={ },
                         doctype='xhtml-transitional', title=self.title)
            return

        login = self.current_user
        argumentList = ['newPassword', 'newPasswdConfirm', 'oldPassword']
        data = { }
        for argument in argumentList:
            try:
                if self.get_argument(argument):
                    data[argument] = self.get_argument(argument)
            except Exception, e:
                pass

        form = ClientPasswordChangeForm()
        try:
            data = form.to_python(data)
            errors = { }

            print "DEBUG: login = %s" % (login)
            self.rpc = bjsonrpc.connect(host=config.ipc.rpcip, port=int(config.ipc.port))
            if not self.rpc.call.checkLogin(config.ipc.apikey, base64.b64encode(login), base64.b64encode(data['oldPassword'].encode('utf-8'))):
                self.set_secure_cookie("message", '<font color="red">Old password is invalid</font>')
                self.redirect('/passwd')
                self.rpc.close()
                return
            try:
                self.rpc.call.changeUserPassword(config.ipc.apikey, base64.b64encode(login), base64.b64encode(data['newPassword'].encode('utf-8')))
                self.set_secure_cookie("message", "Password changed successfully.")
                self.redirect('/')
                self.rpc.close()
                return
            except Exception, e:
                print e
                self.set_secure_cookie("message", 'Error changing password: %s. Contact system administrator.' %(e))
                self.redirect('/')
                return
# 'Invalid' means at least non-matching new password (failed confirmation),
# failing crack.VeryFascistCheck and problems with character encoding
# (see ddtbmanage/forms.py)
        except Invalid, e:
            errors = e.unpack_errors()

        message = "Can't change password."
        self.clear_cookie('message')
        self.render(self.template, message=message, errors=errors,
                     doctype='xhtml-transitional', title=self.title)

class AdminHandler(BaseHandler):
    title = 'TB management console: admin home'
    def get(self):
        if not self.current_user:
            self.redirect('/admin/login')
            return
        if self.get_current_role(self.current_user) != 'admin':
            self.redirect('/')
            return

        message = self.get_secure_cookie("message")
        self.clear_cookie('message')
        self.render('templates/adminIndex.html', message=message, errors={ },
                     doctype='xhtml-transitional', title=self.title)

class AdminLoginHandler(BaseHandler):
    title = 'TB management console: admin login'
    template = 'templates/allLogin.html'

    def get(self):
        if self.current_user:
            if self.get_current_role(self.current_user) != 'admin':
                self.redirect('/')
            else:
                self.redirect('/admin/')
            return

        message = self.get_secure_cookie("message")
        self.clear_cookie('message')
        self.render(self.template, message=message, errors={ },
                     doctype='xhtml-transitional', title=self.title)

    def post(self):
        if self.current_user:
            self.redirect('/admin/')
            return

        message = None
        argumentList = ['user', 'passwd']
        data = { }
        errors = { }

        for argument in argumentList:
            try:
                if self.get_argument(argument):
                    data[argument] = self.get_argument(argument)
            except Exception:
                pass

# This is modified so that user login may contain unicode characters.
# http://tools.ietf.org/html/rfc5572 Figure 12 let's me understand
# there can be unicode characters in login name. This used to be
# formencode.All(validators.PlainText(not_empty=True), validators.MaxLength(30))
# in the forms.py file, but is set to unicode now. I can't see why
# the character set should be limited / 20111022 / CITC

        form = LoginForm()
        try:
            data = form.to_python(data)
#            form.to_python(data)
            if data['user'].encode('utf-8') in hashStore.listUsers() and hashStore.verifyPassword(data['user'], data['passwd']):
                self.set_secure_cookie('user', data['user'])
                self.set_secure_cookie('role', 'admin')
                self.set_secure_cookie('message', 'Admin user successfully logged in.')
                self.redirect('/admin/')
                return
            message = 'Invalid username and/or password'
            self.render(self.template, message=message, errors=errors, doctype='xhtml-transitional', title=self.title)

        except Invalid, e:
            errors = e.unpack_errors()
            self.render(self.template, message=message, errors=errors, doctype='xhtml-transitional', title=self.title)

class AdminUserAddHandler(BaseHandler):

    title = 'TB management console: add new user'
    template = 'templates/userAdd.html'

    def get(self):
        if not self.current_user:
            self.redirect('/admin/login')
            return
        if self.get_current_role(self.current_user) != 'admin':
            self.redirect('/')
            return

        message = self.get_secure_cookie('message')
        self.clear_cookie('message')
        errors = { }
        self.render(self.template, message=message, errors=errors,
                    doctype='xhtml-transitional', title=self.title, login='',
                    name='', email='', mobile='')

    def post(self):
        if not self.current_user :
            self.redirect('/admin/login')
            return
        if self.get_current_role(self.current_user) != 'admin':
            self.redirect('/')
            return

        try:
            self.check_xsrf_cookie()
        except tornado.web.HTTPError, e:
            self.set_secure_cookie("message", "XSRF attempted.")
            message = self.get_secure_cookie("message")
            self.render(self.template, message=message, errors={ },
                         doctype='xhtml-transitional', title=self.title)
            return

        argumentList = ['name', 'login', 'email', 'mobile']
        errors = { }
        data = { }

        for argument in argumentList:
            try:
                if self.get_argument(argument):
                    data[argument] = self.get_argument(argument)
            except Exception:
                pass

        form = ClientAddForm()
        try:
            data = form.to_python(data)
            pg = PasswordGenerator(12)
            passwd = pg.generate()

# Note: X-Forwarded-For is unreliable but apparently best we can have.
            try:
                if not 'X-Forwarded-For' in self.request.headers:
                    self.request.headers['X-Forwarded-For'] = 'localhost'
#                self.rpc.call.addUser(config.ipc.apikey, data['login'],
#                    data['name'], passwd, data['email'], data['mobile'],
#                    self.request.headers['X-Forwarded-For'])

                self.rpc = bjsonrpc.connect(host=config.ipc.rpcip, port=int(config.ipc.port))
                self.rpc.call.addUser(config.ipc.apikey, base64.b64encode(data['login'].encode('utf-8')),
                base64.b64encode(data['name'].encode('utf-8')), base64.b64encode(passwd.encode('utf-8')),
                data['email'], data['mobile'], self.request.headers['X-Forwarded-For'])
                self.rpc.close()
                errors = { }
                self.set_secure_cookie('message', 'User %s successfully added. User password is %s' % (data['login'], passwd))
                self.redirect('/admin/users/manage')
                return
                #TODO: password send via email or SMS
                # SEND SMS VIA: http://www.sms966.com/SMS966WebService/BulkSingleSend.asmx/SendSMS?strUserName=citc&strPassword=citc&strTagName=CITC&strRecepientNumber=<enter_the_phone_no>&strMessage=<message_to_send>
            except Exception, e:
                self.set_secure_cookie('message', '<font color="red">Error adding user, contact system administrator: %s</font>' % (e))
                self.redirect('/admin/')
                return
        except Invalid, e:
           errors = e.unpack_errors()

        message = self.get_secure_cookie('message')
        self.clear_cookie('message')

        # Check for missing values here
        if not 'login' in data:
            data['login'] = ""
        if not 'name' in data:
            data['name'] = ""
        if not 'email' in data:
            data['email'] = ""
        if not 'mobile' in data:
            data['mobile'] = ""

        # Use HTMLFormFiller to pre-populate values
        if data:
            self.render(self.template, message=message, errors=errors,
                        doctype='xhtml-transitional', title=self.title, login=data['login'],
                        name=data['name'], email=data['email'], mobile=data['mobile'])
        else:
             self.render(self.template, message=message, errors=errors,
                        doctype='xhtml-transitional', title=self.title, login='',
                        name='', email='', mobile='')


class AdminUserManageHandler(BaseHandler):
    title = 'TB management console: admin login'
    template = 'templates/userList.html'

    def get(self):
        if not self.current_user:
            self.redirect("/admin/login")
            return
        if self.get_current_role(self.current_user) != 'admin':
            self.redirect('/')
            return

        self.rpc = bjsonrpc.connect(host=config.ipc.rpcip, port=int(config.ipc.port))
        userNameList = self.rpc.call.listUsers(config.ipc.apikey)
        userList = []
        for user in userNameList:
            userList.append(self.rpc.call.userDetails(config.ipc.apikey, unicode(user)))
        self.rpc.close()
        message=self.get_secure_cookie("message")
        self.clear_cookie('message')
        fieldList =  ['login', 'name', 'email', 'mobile']
        self.render(self.template, message=message, doctype='xhtml-transitional',
                    title=self.title, userList=userList, fieldList=fieldList)


class AdminUserChangeHandler(BaseHandler):

    def get(self):
        if not self.current_user:
            self.redirect('/admin/login')
            return
        if self.get_current_role(self.current_user) != 'admin':
            self.redirect('/')
            return

        self.redirect('/admin/users/manage')

    def post(self):
        if not self.current_user:
            self.redirect('/admin/login')
            return
        if self.get_current_role(self.current_user) != 'admin':
            self.redirect('/')
            return

        try:
            self.check_xsrf_cookie()
        except tornado.web.HTTPError, e:
            self.set_secure_cookie("message", "XSRF attempted: %s." % (e.log_message))
            message = self.get_secure_cookie("message")
            self.redirect('/admin/users/manage')
            return

        user_name = 'not set'
        action = 'not set'
        for i in self.request.arguments.iteritems():
            if (i[1][0] == 'Delete' or i[1][0] == 'Reset password'):
                action = i[1][0]
                user_name = i[0]
                break

        if action == 'Delete':
            try:
                self.rpc = bjsonrpc.connect(host=config.ipc.rpcip, port=int(config.ipc.port))
                self.rpc.call.removeUser(config.ipc.apikey, base64.b64encode(user_name))
                self.rpc.close()
                self.set_secure_cookie("message", "User %s successfully removed." % user_name)
                self.redirect('/admin/users/manage')
                return
            except Exception,e:
                self.set_secure_cookie("message", "Error deleting user: %s. Contact system administrator." %(e))
                self.redirect('/admin/users/manage')
                return
        elif action == 'Reset password':
            pg = PasswordGenerator(15)
            passwd = pg.generate()

            try:
                self.rpc = bjsonrpc.connect(host=config.ipc.rpcip, port=int(config.ipc.port))
                self.rpc.call.changeUserPassword(config.ipc.apikey, base64.b64encode(user_name), base64.b64encode(passwd))
                self.rpc.close()
                self.set_secure_cookie("message", "Password for user %s changed. New password is %s" % (user_name, passwd))
                self.redirect("/admin/users/manage")
                return
            except Exception,e:
                self.set_secure_cookie("message", "Could not change password for user %s, password %s: %s. Contact system administrator." % (user_name, '(not shown)' , e))
                self.redirect("/admin/users/manage")
                return
        else:
              self.set_secure_cookie("message", "Something went wrong, action: %s, user: %s." %(action, user_name))
              self.redirect("/admin/users/manage")
 
class AdminUserPasswdHandler(BaseHandler):

    def get(self):
        if not self.current_user :
            self.redirect('/admin/login')
            return
        if self.get_current_role(self.current_user) != 'admin':
            self.redirect('/')
            return

        self.redirect('/admin/users/manage')
        return

    def get(self, user_name):
        if not self.current_user :
            self.redirect('/admin/login')
            return

        if self.get_current_role(self.current_user) != 'admin':
            self.redirect('/')
            return

        try:
            validator = formencode.All(validators.PlainText(not_empty=True),ValidUser())
            login = validator.to_python(user_name)
        except:
            self.set_secure_cookie("message", "User does not exist.")
            self.redirect("/admin/users/manage")
            return

        pg = PasswordGenerator(15)
        passwd = pg.generate()

        try:
            self.rpc = bjsonrpc.connect(host=config.ipc.rpcip, port=int(config.ipc.port))
            self.rpc.call.changeUserPassword(config.ipc.apikey, base64.b64encode(user_name.encode('utf-8')), base64.b64encode(passwd.encode('utf-8')))
            self.rpc.close()
            self.set_secure_cookie("message", "Password for user %s successfully changed. New password is %s" % (user_id, passwd))
            self.redirect("/admin/users/manage")
            return
        except Exception,e:
            self.set_secure_cookie("message", "Could not change password for user %s. Contact system administrator." % (user_id))
            self.redirect("/admin/users/manage")
            return

    def post(self):
        if not self.current_user :
            self.redirect('/admin/login')
            return
        if self.get_current_role(self.current_user) != 'admin':
            self.redirect('/')
            return

        try:
            self.check_xsrf_cookie()
        except tornado.web.HTTPError, e:
            self.set_secure_cookie("message", "XSRF attempted.")
            message = self.get_secure_cookie("message")
            self.redirect('/admin/users/manage')
            return

        user_name = 'not set'
        for i in self.request.arguments.iteritems():
            if i[1][0] == 'Reset password':
                user_name = i[0]
                break

        pg = PasswordGenerator(15)
        passwd = pg.generate()

        try:
            self.rpc = bjsonrpc.connect(host=config.ipc.rpcip, port=int(config.ipc.port))
            self.rpc.call.changeUserPassword(config.ipc.apikey, base64.b64encode(user_name.encode('utf-8')), base64.b64encode(passwd.encode('utf-8')))
            self.rpc.close()
            self.set_secure_cookie("message", "Password for user %s successfully changed. New password is %s" % (user_id, passwd))
            self.redirect("/admin/users/manage")
            return
        except Exception,e:
            self.set_secure_cookie("message", "Could not change password for user. Contact system administrator.")
            self.redirect("/admin/users/manage")
            return

settings = {
    "static_path": os.path.join(os.path.dirname(__file__), "static"),
    "cookie_secret": config.websrv.securecookie,
    "login_url": "/login",
    "debug": True,
    }

application = tornado.web.Application([
    (r"/", MainHandler),
    (r"/login", LoginHandler),
    (r"/passwd", UserPasswdChangeHandler),
    (r"/logoff", LogoffHandler),
    (r"/admin/", AdminHandler),
    (r"/admin", AdminHandler),
    (r"/admin/login", AdminLoginHandler),
    (r"/admin/logoff", AdminLogoffHandler),
    (r"/admin/users/add", AdminUserAddHandler),
    (r"/admin/users/manage", AdminUserManageHandler),
    (r"/admin/users/change", AdminUserChangeHandler),
    (r"/favicon.ico", tornado.web.StaticFileHandler, { "path": "/static/favicon.gif" }),
], **settings)


if __name__ == "__main__":
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(int(config.websrv.port), address=config.websrv.ip)
    print "Opening server on %s port %s" % (config.websrv.ip, config.websrv.port)
    tornado.ioloop.IOLoop.instance().start()
