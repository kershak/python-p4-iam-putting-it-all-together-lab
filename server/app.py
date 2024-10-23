#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def check_if_logged():
    open_access = [
        'signup',
        'login',
        'check_session'
    ]
    if (request.endpoint) not in open_access and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401

class Signup(Resource):
    def post(self):
        data = request.get_json()
        errors = {}

        if 'username' not in data or 'password' not in data:
            return {"error": "Username and password are required."}, 422

        if errors:
            return errors, 422
        try:
            new_user = User(username=data["username"], image_url=data.get("image_url", ""), bio=data.get("bio", ""))
            new_user.password_hash = data["password"]
            db.session.add(new_user)
            db.session.commit()
            session["user_id"] = new_user.id
            return {
                "id": new_user.id,
                "username": new_user.username,
                "image_url": new_user.image_url,
                "bio": new_user.bio
                }, 201
       
        except IntegrityError:
            db.session.rollback()
            errors.setdefault("username", []).append("Username already exists.")
            return errors, 422
        except Exception as e:
            db.session.rollback()
            errors.setdefault("error", []).append(str(e))
            return errors, 422
        
    
        
class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")
        if user_id:
            user = User.query.where(User.id ==user_id).first()
            if user:
                return {
                     "id": user.id,
                    "username": user.username,
                     "image_url": user.image_url,
                     "bio": user.bio
                }, 200
            else:
                session.pop("user_id", None)
                return {}, 401
        else:
            return {}, 401
        # user_id= session.get('user_id')
        # if user_id:
        #     cur_user = User.query.filter(User.id == user_id).first()
        #     return make_response(cur_user.to_dict(), 200)
        # return make_response({'message': 'Not logged in'}, 200)
    
    # def get(self):
    #     user_id= session.get('user_id')
    #     print(f'Session user_id: {user_id}')
    #     if user_id:
    #         cur_user = User.query.filter(User.id ==user_id).first()
    #         if cur_user:
    #             return make_response(cur_user.to_dict(), 200)
    #         else:
    #             return make_response({'message': 'User not found'}, 404)
    #     return make_response({'message': 'Not logged in'}, 200)

class Login(Resource):
    def get(self):
        pass

    def post(self):
        data = request.get_json()

        user = User.query.where(User.username == data["username"]).first()
        if user and user.authenticate(data["password"]):
            session["user_id"] = user.id
            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
                }, 201
        else: 
            return {"Error": "invalid username"}, 401
        
        # data= request.get_json()
        # user = User.query.filter(User.username == data.get('username')).first()
        # if not user:
        #     return make_response({'message': 'Not a valid user'}, 401)
        # if user.authenticate(data.get('password')):
        #     session['user_id'] = user.id
        #     return make_response(user.to_dict(), 201)
        # else:
        #     return make_response({'message': 'Wrong password'}, 401)

class Logout(Resource):
    def delete(self):
        if 'user_id' not in session or session.get('user_id') is None:
            return {"error": "Not logged in"}, 401
        session.pop("user_id")
        return {}, 204
        # session['user_id'] = None
        # return make_response({'message': 'User logged out'}, 200)

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"error": "not logged in"}, 401
        recipes = Recipe.query.filter_by(user_id=user_id).all()
        return [
            {
                "title": recipe.title,
                "instructions":recipe.instructions,
                "minutes_to_complete":recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username,
                    "image_url": recipe.user.image_url,
                    "bio":recipe.user.bio
                }
            }
            for recipe in recipes
        ], 200
    
    def post(self):
        user_id = session.get("user_id")
        
        if not user_id:
            return {"error": "Not logged in"}, 401
        data = request.get_json()

        if not all(key in data for key in ["title", "instructions", "minutes_to_complete"]):
            return {"error": "missing required fields: title, instructions, and minutes_to_complete."}, 422
        if len(data["instructions"]) <50:
            return {"error": "Instructions must be at least 50 characters long."},422
        try:
            new_recipe = Recipe(
                title =data["title"],
                instructions= data["instructions"],
                minutes_to_complete = data["minutes_to_complete"],
                user_id = user_id
            )
            db.session.add(new_recipe)
            db.session.commit()
            user = new_recipe.user

            return {
                "title": new_recipe.title,
                "instructions":new_recipe.instructions,
                "minutes_to_complete":new_recipe.minutes_to_complete,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "image_url": user.image_url,
                    "bio":user.bio
                }
            }, 201
        except IntegrityError:
            db.session.rollback()
            return {"error":"There was an issue with the data provided"}, 422
        except Exception as e:
            return {"error": str(e)}, 500
    #def get(self):
        # user = User.query.filter_by(id=session['user_id']).first()
        # recipe_list = [recipe.to_dict() for recipe in user.recipes]
        # return make_response(recipe_list, 200)

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)