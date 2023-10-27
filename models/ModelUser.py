from .entities.User import User
from flask import flash
import bcrypt


class ModelUser():

    @classmethod
    def login(self, db, user):
        try:
            cursor = db.connection.cursor()
            sql = """SELECT id, username, password, fullname, tipo_user FROM user 
                    WHERE username = %s"""
            cursor.execute(sql, (user.username,))
            row = cursor.fetchone()
            if row is not None:
                hashed_password = row[2].encode('utf-8')  # Codifica la contraseña almacenada en bytes
                provided_password = user.password.encode('utf-8')  # Codifica la contraseña proporcionada en bytes
                is_valid_password = bcrypt.checkpw(provided_password, hashed_password)
                if is_valid_password:
                    user = User(row[0], row[1], row[2], row[3], row[4])
                    return user
                else:
                    return None
            else:
                return None
        except Exception as ex:
            raise Exception(ex)
        
    @classmethod
    def get_by_id(self, db, id):
        try:
            cursor = db.connection.cursor()
            sql = "SELECT id, username, fullname FROM user WHERE id = {}".format(id)
            cursor.execute(sql)
            row = cursor.fetchone()
            if row != None:
                return User(row[0], row[1], None, row[2])
            else:
                return None
        except Exception as ex:
            raise Exception(ex)

    @classmethod
    def register(cls, db, user, confirm_password):
        try:
            # Verifica si el usuario ya existe en la base de datos
            cursor = db.connection.cursor()
            
            # Hashea la contraseña antes de guardarla en la base de datos
            hashed_password = cls.hash_password(user.password)
            
            # Agrega el nuevo campo 'tipo_user' con valor predeterminado '0'
            sql = """INSERT INTO user (username, password, fullname, tipo_user)
                    VALUES (%s, %s, %s, %s)"""
            
            cursor.execute(sql, (user.username, hashed_password, user.fullname, 0))
            db.connection.commit()
            cursor.close()
            return True
        except Exception as ex:
            flash("Usuario ya registrado")
            return False  # Indica que el registro no fue exitoso

    @classmethod
    def get_by_username(cls, db, username):
        try:
            cursor = db.connection.cursor()
            sql = "SELECT id, username, password, fullname FROM user WHERE username = %s"
            cursor.execute(sql ,(username,))
            row = cursor.fetchone()
            if row is not None:
                user = cls(row[0], row[1], row[2], row[3])
                return user
            else:
                return None
        except Exception as ex:
            # Captura y maneja la excepción aquí, y regresa None en caso de error
            return None


    @staticmethod
    def hash_password(password):
        # Genera un salt aleatorio
        salt = bcrypt.gensalt()
        # Hashea la contraseña con el salt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password