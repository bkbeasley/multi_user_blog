#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


import webapp2
import jinja2
import re
from google.appengine.ext import db
import os
import hmac
from libs import bcrypt


#Load the template and setup the jinja environment
template_dir = os.path.dirname(__file__)
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), 
                               autoescape = False)


class User(db.Model):
    """Data model storing the attributes of each User.

       username: unique username of a user stored as a string property
       password: password of a user stored as a string property
       email: user's email address as a string property
    """
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()

class BlogPost(db.Model):
    """Data model storing the attributes of each BlogPost.

       author: username of the user that created the post stored as a string
       title: title of the post stored as a string
       content: text property storing the main content of a post
       subtitle: text property storing the first 100 characters of content
       created: DateTime property storing when the post was created
       like_counter: stores the number of likes a post has
    """
    author = db.StringProperty(required = True)
    title = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    subtitle = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    like_counter = db.IntegerProperty(required = True)

class Comment(db.Model):
    """Data model storing the attributes for each Comment

       content: the actual content of a Comment stored as a text property
       post: 
       author: the username of the user that submitted the comment
       created: DateTkime property storing when the comment was submitted
    """
    content = db.TextProperty(required = True)
    post = db.ReferenceProperty(BlogPost, collection_name = "comments")
    author = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class Like(db.Model):
    """Data model storing the attributes for each Like

       author: the username of the user that liked the 
       post: 
    """
    author = db.StringProperty(required = True)
    post = db.ReferenceProperty(BlogPost, collection_name = "likes")


class Handler(webapp2.RequestHandler):
    """Contains the logic to handle a request and render a page using 
    a template.
    """
    def write(self, *args, **kwargs):
        """Displays values passed in *args, and **kwargs to the page
        """
        self.response.write(*args, **kwargs)

    def render_str(self, template, **kwargs):
        """Loads the template to be rendered and returns it.
        """
        t = jinja_env.get_template(template)
        return t.render(kwargs)

    def render(self, template, **kwargs):
        """Render the page using a template.
        """
        self.write(self.render_str(template, **kwargs))

    def set_cookie(self, cookie_name, cookie_value):
        """Sets a secure, hashed cookie pertaining to the user's id.

        Args:
            cookie_name: string that indicates the name of a cookie in the header
            cookie_value: hashed value of the cookie
        """
        #Stores a hashed cookie value
        val = hash_cookie_value(cookie_value)

        #Set the cookie
        self.response.headers.add_header(
            "Set-Cookie",
            "%s=%s; Path=/" % (cookie_name, val))


class FrontPage(Handler):
    """Displays posts on GET requests and redirects to the login and signup
    pages on POSTS requests.
    """
    def get(self):
        #Retrieve all of the BlogPosts in the datastore and store them
        posts = db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC")

        #Store the value of the user_id cookie
        user_cookie = self.request.cookies.get("user_id")

        #Stores the current user entity if a user is logged in
        user = None

        if user_cookie:
            """Get the unhashed cookie value and use it to retrieve the User 
            entity for a logged in user
            """
            cookie_value = unhash_cookie_value(user_cookie)
            cookie_value = int(cookie_value)

            key = db.Key.from_path("User", cookie_value)

            if not key:
                self.error(404)
                return
            else:
                user = db.get(key)

        self.render("index.html", posts = posts, user = user)

class Login(Handler):
    """Validates the login information provided by the user and responds
       appropriately by either informing the user of an error or signing them
       in and redirecting them to the front page.
    """
    def get(self):
        #Retrieve the value of the user_id cookie
        user_cookie = self.request.cookies.get("user_id")

        if user_cookie:
            self.redirect('/')
        else:
            self.render("login_page.html")

    def post(self):
        #Retrieve and store the username and password input by the user
        username = self.request.get("username")
        password = self.request.get("password")

        #Validate the user's input
        current_user = retrieve_user(username)

        #String displayed upon invalid login attempt
        login_error = "Incorrect username or password."
        
        """
        If the username input is in the datastore and if the password
        is correct log in the user. If not display an error.
        """
        if current_user and match_hashed(username, password):
            #Used to validate whether or not a User is logged in
            self.set_cookie("user_id", current_user.key().id())

            self.redirect('/')
        else:
            self.render("login_page.html", login_error = login_error)


class Register(Handler):
    """Creates and stores a unique User in the datastore.

    Displays either the logout page or register page depending on whether or not
    a user is logged in, on GET requests. 

    Sets the user_id cookie and redirects the user to the front page upon POST
    requests.
    """
    def get(self):
        """If a user is already logged in redirect them to logout,
        if a user is not signed in, render the register page.
        """
        user_cookie = self.request.cookies.get("user_id")

        if user_cookie:
            self.redirect('/logout')
        else:
            self.render("register_page.html")

    def post(self):
        #Used to determine if their was an invalid field
        error_flag = False

        #Retrieve and store the fields input by the user
        username = self.request.get("username")
        password = self.request.get("password")
        verify_pass = self.request.get("verify_pass")
        email = self.request.get("email")

        #Passed to the template
        dict = {}

        #Determine if the User already exists
        current_user = retrieve_user(username)

        #Validate the user's input
        if not valid_username(username):
            error_flag = True
            dict["username_error"] = "Invalid username."

        if not valid_password(password):
            error_flag = True
            dict["password_error"] = "Invalid password."
        elif verify_pass != password:
            error_flag = True
            dict["verify_error"] = "Passwords do not match."

        if email:
            if not valid_email(email):
                error_flag = True
                dict["email_error"] = "Invalid email address."

        #If the username already exists in the datastore
        if current_user:
            error_flag = True
            dict["user_exists_error"] = "This username is taken. Please try a different username."

        #Re-render the page and display invalid input errors
        if error_flag:
            self.render("register_page.html", **dict)
            return

        #Hash the user's password
        hashed_pass = bcrypt.hashpw(password, bcrypt.gensalt())

        #Create and store a new user
        new_user = User(username = username, password = hashed_pass, email = email)
        new_user.put()

        #Log ther user in and redirect them to the front page
        self.set_cookie("user_id", new_user.key().id())
        self.redirect('/')

class SubmitPost(Handler):
    """Allows a user to submit a new blog post.

    Displays the submit post page on GET requests if a user is logged in.

    Adds a new BlogPost to the datastore and redirects the user to a permalink
    of that BlogPost upon POST requests.
    """
    def get(self):
        #Retrieve the value of the user_id cookie
        user_cookie = self.request.cookies.get("user_id")

        #Stores the current user entity if a user is logged in
        user = None

        """If the user is logged in, retrieve the appropriate User entity
        from the datastore, if not render the login page.
        """
        if user_cookie:
            cookie_value = unhash_cookie_value(user_cookie)
            cookie_value = int(cookie_value)

            user_key = db.Key.from_path("User", cookie_value)

            if not user_key:
                self.error(404)
                return
            else:
                user = db.get(user_key)
            self.render("submit_post.html", user = user)
        else:
            self.redirect('/login')

    def post(self):
        user_cookie = self.request.cookies.get("user_id")

        user = None

        if user_cookie:
            cookie_value = unhash_cookie_value(user_cookie)
            cookie_value = int(cookie_value)

            key = db.Key.from_path("User", cookie_value)

            user = None

            if not key:
                self.error(404)
                return
            else:
                user = db.get(key)

                #Used to determine if there was an invalid field
                error_flag = False

                error_msg = "Please enter both a title and content."

                #Retrieve and store the fields input by the user
                title = self.request.get("title")
                content = self.request.get("content")
                author = user.username

                if not title:
                    error_flag = True
                
                #If the user does not input a string 
                if not content:
                    error_flag = True
                elif not content.strip():
                    error_flag = True

                if error_flag:
                    self.render("submit_post.html", error_msg = error_msg)
                else:
                    #Store the first 100 characters of the user's content
                    subtitle = content[0:100]
                    
                    #Store the BlogPost in the datastore
                    new_post = BlogPost(author = author, title = title, content = content, subtitle = subtitle, like_counter = 0)
                    new_post.put()

                    self.redirect('/post/%s' % str(new_post.key().id()))

class PermalinkPost(Handler):
    """Directs users to a permalink of a specific post.

    Renders a post and its likes and comments on GET requests, and allows the
    user to like a post or comment on POST requests.
    """
    def get(self, post_id):
        #Retrieve the value of the user_id cookie
        user_cookie = self.request.cookies.get("user_id")
        
        """Flag used to determine if the currently logged in user created
        the post.
        """
        valid_user = False

        user = None
        
        #Used to store the username of a User
        username = ""

        #Attempt to retrieve the User from the datastore
        if user_cookie:
            cookie_value = unhash_cookie_value(user_cookie)
            cookie_value = int(cookie_value)

            user_key = db.Key.from_path("User", cookie_value)

            if not user_key:
                self.error(404)
                return
            else:
                user = db.get(user_key)
                username = user.username

        #Attempt to retrieve the BlogPost from the datastore
        blog_key = db.Key.from_path("BlogPost", int(post_id))

        if not blog_key:
            self.error(404)
            return
        else:
            post = db.get(blog_key)

            #Stores the comments of the BlogPost
            comment_list = []

            #Store the comments in the list 
            for comment in post.comments:
                comment_list.append(comment)

            """Sort the comments in the list in descending post order, i.e. 
            newest comments first.
            """
            comment_list.sort(key = lambda r: r.created, reverse = True)

            if user and user.username == post.author:
                valid_user = True

            self.render("permalink_post.html", post = post, comments = comment_list, valid_user = valid_user, username = username)

    def post(self, post_id):
        #Retrieve the user's comment and the user_id cookie value
        user_comment = self.request.get("comment")
        user_cookie = self.request.cookies.get("user_id")

        user = None
        

        if user_cookie:
            cookie_value = unhash_cookie_value(user_cookie)
            cookie_value = int(cookie_value)

            blog_key = db.Key.from_path("BlogPost", int(post_id))

            if not blog_key:
                self.error(404)
                return
            else:
                post = db.get(blog_key)

                user_key = db.Key.from_path("User", cookie_value)

                if not user_key:
                    self.error(404)
                    return
                else:
                    user = db.get(user_key)

                #Flag used to determine if a user has previously like the post
                prev_liked = False

                #Set the variable prev_liked to true if the user liked the post previously
                for like in post.likes:
                    if user.username == like.author:
                        prev_liked = True
                        break
                
                #Increment the like_counter by 1 and update the BlogPost
                if not prev_liked:
                    Like(author = user.username, post = post).put()
                    post.like_counter += 1
                    post.put()

                #Add the Comment to the datastore
                if user_comment:
                    Comment(content = user_comment, post = post, author = user.username).put()

                self.redirect('/')
        #If the user is not logged in redirect them to the login page
        else:
            self.redirect('/login')


class Logout(Handler):
    """Logs the user out by setting the setting an empty cookie
    in the response header.
    """
    def get(self):
        #Set the value of user_id to an empty string
        self.response.headers.add_header(
            "Set-Cookie",
            "user_id=""; Path=/")

        self.redirect('/')

class EditPost(Handler):
    """Allows the user to edit their post.

    Displays a form to allow the user to edit their post on GET requests.

    Updates an edited post and updates its contents in the datastore on POSTS
    requests.
    """
    def get(self, post_id):
        user_cookie = self.request.cookies.get("user_id")
        user = None

        if user_cookie:
            cookie_value = unhash_cookie_value(user_cookie)
            cookie_value = int(cookie_value)
            user_key = db.Key.from_path("User", cookie_value)

            if not user_key:
                self.error(404)
                return
            else:
                user = db.get(user_key)

                blog_key = db.Key.from_path("BlogPost", int(post_id))

                if not blog_key:
                    self.error(404)
                    return
                else:
                    blog_post = db.get(blog_key)

                    if user.username == blog_post.author:            
                        title = blog_post.title
                        content = blog_post.content

                        self.render("edit_post.html", title = title, content = content, user = user)
                    else:
                        self.redirect("/")

        else:
            self.redirect('/login')

    def post(self, post_id):
        user_cookie = self.request.cookies.get("user_id")

        user = None

        if user_cookie:
            cookie_value = unhash_cookie_value(user_cookie)
            cookie_value = int(cookie_value)

            blog_key = db.Key.from_path("BlogPost", int(post_id))

            if not blog_key:
                self.error(404)
                return
            else:
                blog_post = db.get(blog_key)
                content = blog_post.content

                #Used to determine if there was an invalid field
                error_flag = False

                error_msg = "Please enter both a title and content."

                #Retrieve and store the fields input by the user
                new_title = self.request.get("title")
                new_content = self.request.get("content")
                
                if not new_title:
                    error_flag = True
                
                #If the user does not input a string 
                if not new_content:
                    error_flag = True
                elif not new_content.strip():
                    error_flag = True

                if error_flag:
                    self.render("edit_post.html", error_msg = error_msg)
                #Update the BlogPost with the edited items
                else:
                    new_subtitle = new_content[0:100]

                    blog_post.title = new_title
                    blog_post.content = new_content
                    blog_post.subtitle = new_subtitle
                    blog_post.put()

                    self.redirect('/post/%s' % str(blog_post.key().id()))


class DeletePost(Handler):
    """Deletes a user's BlogPost in the datastore.
    """
    def get(self, post_id):
        #Retrive the Blog entity key
        blog_key = db.Key.from_path("BlogPost", int(post_id))

        if not blog_key:
            self.error(404)
            return
        else:
            #Store the BlogPost and delete it
            post = db.get(blog_key)
            post.delete()

            self.redirect('/')


class Contact(Handler):
    """Displays the contact page.
    """
    def get(self):
        #Retrieve the user_id cookie
        user_cookie = self.request.cookies.get("user_id")

        #Stores an entity of User if one is found.
        user = None

        if user_cookie:
            #Retrieve the User id from the cookie 
            cookie_value = unhash_cookie_value(user_cookie)
            cookie_value = int(cookie_value)

            #Stores the value of the User entity key 
            user_key = db.Key.from_path("User", cookie_value)

            #Assign user to the correct User in the datastore, or issue an error
            if not user_key:
                self.error(404)
                return
            else:
                user = db.get(user_key)

        self.render("contact.html", user = user)

def valid_username(username):
    """Determines whether or not a username is valid.

    Args: 
        username: A string representing the name used in input by a user.

    Returns: 
        A boolean value depending on whether or not the string matches the 
        regular expression.
    """
    #Store the regular expression required of a user's username.
    user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

    return user_re.match(username)

def valid_password(password):
    """Determines whether or not a password is valid.

    Args:
        password: A string representing the password used in input by a user.

    Returns: 
        A boolean value depending on whether or not the string matches the 
        regular expression.
    """
    #Store the regular expression required of a user's password.
    password_re = re.compile(r"^.{3,20}$")

    return password_re.match(password)

def valid_email(email):
    """Determines whether or not an email address is valid.

    Args:
        email: A string representing the email used in input by a user.

    Returns:
        A boolean value depending on whether or not the string matches the
        regular expression.
    """
    #Store the regular expression required of a user's email.
    email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")

    return email_re.match(email)

def retrieve_user(username):
    """Determines if a User is stored in the DataStore.

    Args:
        username: A string storing the username.

    Returns:
        A current_user entity if one exists.
    """
    #If found, stores a reference to the User
    current_user = None

    #Perform a query and attempt to get the User
    current_user = db.GqlQuery("SELECT * FROM User WHERE username = :username", 
                               username = username).get()   
    return current_user

def match_hashed(username, password):
    """Determines if an unecrypted password matches one that has previously
    been hashed.

    Args:
        username: A string storing the input username.
        password: A string storing the input password.
    Returns:
        If the input username and password match a User entity currently 
        stored in the datastore, the function returns True. If not, the 
        function returns false.
    """
    #Used to retrieve the User entity and the hashed password
    current_user = retrieve_user(username)

    #If the username is found within the datastore.
    if current_user:
        hashed_password = current_user.password

        #Attempt to match the unencrypted password to the encrypted one
        hashed_password2 = bcrypt.hashpw(password, hashed_password)

        #If the passwords match
        if hashed_password == hashed_password2:
            return True

    return False

def hash_cookie_value(cookie_value):
    """Uses hmac to hash the user's id.

    Args:
        cookie_value: The value of the User's entity id in the datastore.

    Returns: 
        A string separated by a pipe, storing the User's entity id in the first
        part, and the newly hashed value in the second part.
    """

    #Convert the entity id into a string
    cookie_value = str(cookie_value)

    return "%s|%s" % (cookie_value, hmac.new(SECRET, cookie_value).hexdigest())

def unhash_cookie_value(hashed_value):
    """"Determines if the hashed value passed matches the cookie value stored.

    Args: 
        hashed_value: Value for the cookie "user_id". 

    Returns:
        The unhashed value of the cookie if hashed_value matches, and False
        if hashed_value does not match.
    """
    #Stores the first part of the "user_id" cookie
    val = hashed_value.split('|')[0]

    if hashed_value == hash_cookie_value(val):
        return val

"""Used in conjunction with hmac to hash a cookie value. Ideally, this variable
   should be stored in a separate file, but for demonstration purposes, this 
   variable will remain here.
"""
SECRET = "D%#03MfiAi72nj~i6lpOKDb9dfey!iM"

#Initialize the web application and handlers
app = webapp2.WSGIApplication([
('/', FrontPage), ('/login', Login), ('/register', Register), ('/submit', SubmitPost), ('/post/([0-9]+)', PermalinkPost), ('/logout', Logout), ('/post/([0-9]+)/edit', EditPost), ('/post/([0-9]+)/delete', DeletePost), ('/contact', Contact)
], debug=True)
