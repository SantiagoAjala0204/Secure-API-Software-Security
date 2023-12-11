import os
from flask import Flask, request, jsonify, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_security import RoleMixin
from flask_security import login_user
from flask_security import UserMixin
from flask_security import Security
from flask_security import SQLAlchemySessionUserDatastore
from flask_login import LoginManager, login_user
from pytz import timezone
from sqlalchemy import text
from flask_limiter import Limiter
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import logging


# Flask app setup
app = Flask(__name__)

# Timezone setup
tz = timezone('America/Bogota')  

# Rate limiting setup
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://"
)
# Configure the logger
logger = logging.getLogger(__name__)


# Session cookies
app.config['SECRET_KEY'] = 'MY_SECRET'
# Hashes the password and then stores in the database
app.config['SECURITY_PASSWORD_SALT'] = "MY_SECRET"
# Allows new registrations to application
app.config['SECURITY_REGISTERABLE'] = True
# Send automatic registration email to user
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False
# JWT Configuration
app.config['JWT_SECRET_KEY'] = 'abcxyz'
# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # SQLite database file name
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:db2023LOCATION@34.176.104.247:3306/db_get_location'
jwt = JWTManager(app)


# SQLAlchemy setup
db = SQLAlchemy(app)

#Fuction to save the data in audit_log table
def log_audit(user_id, method, log_level, message):
    # Obtiene el ID del usuario si user_id es un objeto Usuario
    user_id = getattr(user_id, 'id', user_id)

    nuevo_registro = AuditLog(
        user_id=user_id,
        method=method,
        log_level=log_level,
        timestamp=datetime.now(tz),
        message=message
    )

    db.session.add(nuevo_registro)
    db.session.commit()


# Define el modelo de usuario y roles
roles_users = db.Table('roles_users',
    db.Column('user_id', db.String(10), db.ForeignKey('usuario.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Rol(db.Model, RoleMixin):
    __tablename__ = 'role'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)

# User model
class Usuario(db.Model):
    __tablename__ = 'usuario'
    id = db.Column(db.String(10), primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellido = db.Column(db.String(100), nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    activo = db.Column(db.Boolean(), default=True, nullable=False)
    created_date = db.Column(db.DateTime, default=datetime.now(tz), nullable=False)
    roles = db.relationship('Rol', secondary=roles_users, backref='roled')
    puntos = db.relationship('Punto', backref='usuario', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_active(self):
        return self.active


# Point model
class Punto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    latitud = db.Column(db.String(20), nullable=False)
    longitud = db.Column(db.String(20), nullable=False)
    fecha = db.Column(db.DateTime, default=lambda: datetime.now(tz))
    usuario_id = db.Column(db.String(10), db.ForeignKey('usuario.id'), nullable=False)

# Audit Model
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(10), nullable=True)
    method = db.Column(db.String(10), nullable=True)
    log_level = db.Column(db.String(10), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.now(tz), nullable=False)
    message = db.Column(db.String(255), nullable=True)

# Agregar roles a la base de datos
with app.app_context():
    #db.create_all()

    # Crear roles si no existen
    for role_name in ["admin", "user"]:
        existing_role = Rol.query.filter_by(name=role_name).first()
        if not existing_role:
            new_role = Rol(name=role_name)
            db.session.add(new_role)
    
    db.session.commit()



# load users, roles for a session
user_datastore = SQLAlchemySessionUserDatastore(db.session, Usuario, Rol)
# security = Security(app, user_datastore)
#ERRORES
@app.errorhandler(500)
def internal_server_error(e):
    return jsonify(error=str(e)), 500
# Add User
@app.route('/agregar_usuario', methods=['POST'])
def agregar_usuario():
    data = request.get_json()
    if 'id' in data and 'nombre' in data and 'password_hash' in data and 'role' in data:
        id_usuario = data['id']
        nombre = data['nombre']
        apellido = data.get('apellido', None)
        contraseña = data['password_hash']
        role = data['role']

        # Verificar si el ID del usuario ya existe en la base de datos
        usuario_existente = Usuario.query.filter_by(id=id_usuario).first()
        if usuario_existente:
            log_audit(usuario_existente, request.method, 'WARNING', f"Intento de agregar usuario existente con ID {usuario_existente}")
            return jsonify({'message': 'Usuario ya registrado'}), 400
        else:
            # Buscar el rol en la base de datos
            rol_existente = Rol.query.filter_by(name=role).first()

            if rol_existente:
                nuevo_usuario = Usuario(id=id_usuario, nombre=nombre, apellido=apellido)
                nuevo_usuario.set_password(contraseña)
                # Asignar roles al nuevo usuario
                nuevo_usuario.roles.append(rol_existente)
                db.session.add(nuevo_usuario)
                db.session.commit()
                # Iniciar sesión automáticamente con el nuevo usuario
                #login_user(nuevo_usuario)
                log_audit(id_usuario, request.method, 'INFO', f"Usuario {id_usuario} agregado correctamente")
                return jsonify({'message': 'Usuario agregado correctamente', 'id': nuevo_usuario.id}), 201
            else:
                return jsonify({'error': 'El rol especificado no existe'}), 400
    else:
        return jsonify({'error': 'Los campos id, nombre, password_hash y role son requeridos'}), 400

# Get User
@app.route('/obtener_usuarios', methods=['GET'])
@limiter.limit("5 per minute")  # 5 requests per minute
@jwt_required()
def obtener_usuarios():
    # Autenticar al usuario utilizando el token JWT
    current_user = get_jwt_identity()
    if not current_user:
        log_audit(current_user, request.method, 'ERROR', f"Usuario {current_user} no posee su token para acceder a la lista de usuarios")
        return jsonify({'error': 'Se requiere autenticación'}), 401

    log_audit(current_user, request.method, 'INFO', f"Usuario {current_user} accedió a la lista de usuarios")

    # Obtener información de los usuarios
    usuarios = Usuario.query.all()
    
    # Crear una lista de diccionarios con la información de cada usuario
    usuarios_json = [
        {
            'id': usuario.id,
            'nombre': usuario.nombre,
            'apellido': usuario.apellido,
            'activo': usuario.activo,
            'creado': usuario.created_date,
            'role': usuario.roles[0].name  # Suponiendo que un usuario tiene solo un rol
        }
        for usuario in usuarios
    ]

    # Crear la respuesta JSON
    response = {'users': usuarios_json, 'user': current_user}
    return jsonify(response)


# Add point
@app.route('/agregar_punto', methods=['POST'])
@limiter.limit("5 per minute")  # 5 requests per minute
@jwt_required()
def agregar_punto():
    # Authenticate user using JWT token
    current_user = get_jwt_identity()

    # Query the database or another source to get the roles for the current user
    user = Usuario.query.filter_by(id=current_user).first()
    roles = user.roles  # Assuming 'roles' is a property or attribute of the Usuario model

    # Check if the user has the 'admin' role
    if 'user' not in roles:
        log_audit(current_user, request.method, 'ERROR', f"Usuario {current_user} no tiele el rol para agregar un punto")
        return jsonify({'error': 'Permission denied. Admin role required.'}), 403

    data = request.get_json()
    if 'latitud' in data and 'longitud' in data and 'usuario_id' in data:
        latitud = data['latitud']
        longitud = data['longitud']
        usuario_id = data['usuario_id']
        nuevo_punto = Punto(latitud=latitud, longitud=longitud, usuario_id=usuario_id)
        db.session.add(nuevo_punto)
        db.session.commit()
        log_audit(usuario_id, request.method, 'INFO', f"El usuario {usuario_id} agregó un punto")
        return jsonify({'message': 'Punto agregado correctamente', 'id': nuevo_punto.id}), 201
    else:
        return jsonify({'error': 'Los campos de latitud, longitud y usuario_id son requeridos'}), 400

# Get points
@app.route('/obtener_puntos', methods=['GET'])
@limiter.limit("5 per minute")  # 5 requests per minute
@jwt_required()
def obtener_puntos():
    # Authenticate user using JWT token
    current_user = get_jwt_identity()
    if not current_user:
        log_audit(current_user, request.method, 'ERROR', f"Usuario {current_user} no posee su token para obtener la lista de puntos")
        return jsonify({'error': 'Authentication required', 'user' : current_user}), 401
    
    # Query the database or another source to get the roles for the current user
    user = Usuario.query.filter_by(id=current_user).first()
    roles = user.roles  # Assuming 'roles' is a property or attribute of the Usuario model

    # Check if the user has the 'admin' role
    if 'admin' not in roles:
        log_audit(current_user, request.method, 'ERROR', f"Usuario {current_user} no tiene el rol para obtener la lista de puntos")
        return jsonify({'error': 'Permission denied. Admin role required.'}), 403
    
    
    log_audit(current_user, request.method, 'INFO', f"Usuario {current_user} accedió a la lista de puntos")
    puntos = Punto.query.all()
    puntos_json = [{'id': punto.id, 'latitud': punto.latitud, 'longitud': punto.longitud, 'fecha': punto.fecha, 'usuario_id': punto.usuario_id} for punto in puntos]
    return jsonify({'puntos': puntos_json})

# Delete point using id
@app.route('/eliminar_puntos/<string:usuario_id>', methods=['DELETE'])
@limiter.limit("5 per minute")  # 5 requests per minute
@jwt_required()
def eliminar_puntos_por_usuario(usuario_id):
    # Authenticate user using JWT token
    current_user = get_jwt_identity()
    if not current_user:
        log_audit(current_user, request.method, 'ERROR', f"Usuario {current_user} no posee su token para eliminar los puntos")
        return jsonify({'error': 'Authentication required'}), 401
    # Verificar si el usuario existe en la base de datos
    usuario = Usuario.query.get(usuario_id)
    
    if usuario is None:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    
    # Eliminar los puntos asociados a ese usuario
    puntos_eliminados = Punto.query.filter_by(usuario_id=usuario_id).delete()
    db.session.commit()
    log_audit(usuario_id, request.method, 'WARNING', f"Usuario {usuario_id} acaba de eliminar sus puntos")
    return jsonify({'message': f'Se eliminaron {puntos_eliminados} puntos del usuario con ID {usuario_id}'}), 200

# Delete 
@app.route('/eliminar_puntos', methods=['DELETE'])
@limiter.limit("5 per minute")  # 5 requests per minute
@jwt_required()
def eliminar_puntos():
    # Authenticate user using JWT token
    current_user = get_jwt_identity()
    if not current_user:
        log_audit(current_user, request.method, 'ERROR', f"Usuario {current_user} no posee su token para obtener eliminar los puntos.")
        return jsonify({'error': 'Authentication required'}), 401
    try:
        # Eliminar todos los registros de la tabla Punto
        num_registros_eliminados = db.session.query(Punto).delete()
        db.session.commit()
        # Reiniciar la secuencia de incremento del campo "id" en MySQL
        if db.engine.dialect.name == 'mysql':
            db.session.execute(text('ALTER TABLE punto AUTO_INCREMENT = 1'))
            db.session.commit()
        return jsonify({'message': f'Se eliminaron {num_registros_eliminados} registros correctamente'}), 200
    except Exception as e:
        app.logger.error(f'Error al eliminar puntos: {str(e)}')
        db.session.rollback()
        return jsonify({'error': 'Ocurrió un error al eliminar los registros'}), 500
    
# Delete user by id
@app.route('/eliminar_usuario/<string:id>', methods=['DELETE'])
@limiter.limit("5 per minute")  # 5 requests per minute
@jwt_required()
def eliminar_usuario(id):
    # Authenticate user using JWT token
    current_user = get_jwt_identity()
    if not current_user:
        log_audit(current_user, request.method, 'ERROR', f"Usuario {current_user} no posee su token para eliminar usuarios")
        return jsonify({'error': 'Authentication required'}), 401
    log_audit(current_user, request.method, 'WARNING', f"El usuario {current_user} acaba de eliminarse de la base de datos")
    usuario = Usuario.query.get(id)
    if usuario is None:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    db.session.delete(usuario)
    db.session.commit()
    return jsonify({'message': f'Usuario con ID {id} eliminado correctamente'}), 200

# Delete all users
@app.route('/eliminar_usuarios', methods=['DELETE'])
@limiter.limit("5 per minute")  # 5 requests per minute
@jwt_required()
def eliminar_usuarios():
    # Authenticate user using JWT token
    current_user = get_jwt_identity()
    if not current_user:
        log_audit(current_user, request.method, 'ERROR', f"Usuario {current_user} no posee su token para eliminar todos los usuarios")        
        return jsonify({'error': 'Authentication required'}), 401
    try:
        num_usuarios_eliminados = db.session.query(Usuario).delete()
        db.session.commit()
        log_audit(current_user, request.method, 'WARNING', f"Usuario {current_user} acaba de eliminar todos los usuarios")
        return jsonify({'message': f'Se eliminaron {num_usuarios_eliminados} usuarios correctamente'}), 200
    except Exception as e:
        app.logger.error(f'Error al eliminar usuarios: {str(e)}')
        db.session.rollback()
        return jsonify({'error': 'Ocurrió un error al eliminar los usuarios'}), 500
    
# Get points by user
@app.route('/obtener_puntos_por_usuario/<string:usuario_id>', methods=['GET'])
@limiter.limit("5 per minute")  # 5 requests per minute
@jwt_required()
def obtener_puntos_por_usuario(usuario_id):
    # Authenticate user using JWT token
    current_user = get_jwt_identity()
    if not current_user:
        log_audit(current_user, request.method, 'ERROR', f"Usuario {current_user} no posee su token para obtener la lista de puntos por usuario")
        return jsonify({'error': 'Authentication required'}), 401
    puntos = Punto.query.filter_by(usuario_id=usuario_id).all()
    if not puntos:
        log_audit(current_user, request.method, 'ERROR', f"Usuario {current_user} no posee puntos para eliminar")
        return jsonify({'error': 'No se encontraron puntos para el usuario con ID ' + usuario_id}), 404
    puntos_json = [{'id': punto.id, 'latitud': punto.latitud, 'longitud': punto.longitud, 'fecha': punto.fecha, 'usuario_id': punto.usuario_id} for punto in puntos]
    log_audit(current_user, request.method, 'INFO', f"Usuario {current_user} accedió a su lista de puntos")
    return jsonify({'puntos': puntos_json})

# Get points within a time range for a specific user
@app.route('/obtener_puntos_por_rango_de_tiempo/<string:usuario_id>', methods=['GET'])
@limiter.limit("5 per minute")  # 5 requests per minute
def obtener_puntos_por_rango_de_tiempo(usuario_id):
    # Authenticate user using JWT token
    current_user = get_jwt_identity()
    if not current_user:
        log_audit(current_user, request.method, 'ERROR', f"Usuario {current_user} no posee su token para obtener la lista de puntos en un rango de tiempo")
        return jsonify({'error': 'Authentication required'}), 401
    start_time_str = request.args.get('start_time')
    end_time_str = request.args.get('end_time')

    if not start_time_str or not end_time_str:
        return jsonify({'error': 'Los parámetros start_time y end_time son requeridos'}), 400

    start_time = datetime.strptime(start_time_str, '%Y-%m-%d %H:%M:%S').astimezone(tz)
    end_time = datetime.strptime(end_time_str, '%Y-%m-%d %H:%M:%S').astimezone(tz)

    puntos = Punto.query.filter_by(usuario_id=usuario_id).filter(Punto.fecha >= start_time, Punto.fecha <= end_time).all()

    if not puntos:
        return jsonify({'error': 'No se encontraron puntos para el usuario con ID ' + usuario_id + ' en el rango de tiempo especificado'}), 404
    puntos_json = [{'id': punto.id, 'latitud': punto.latitud, 'longitud': punto.longitud, 'fecha': punto.fecha.strftime('%Y-%m-%d %H:%M:%S %Z'), 'usuario_id': punto.usuario_id} for punto in puntos]
    log_audit(current_user, request.method, 'INFO', f"Usuario {current_user} accedió a su lista de puntos en un rango de tiempo")
    return jsonify({'puntos': puntos_json})

# Authentication endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if the provided username exists in the database
    user = Usuario.query.filter_by(id=username).first()

    if user and check_password_hash(user.password_hash, password):
        # Obtain user roles (modify this based on how you store roles in your application)
        roles = [role.name for role in user.roles]

        # Create JWT token with identity and roles
        access_token = create_access_token(identity=username, additional_claims={'roles': roles})

        log_audit(username, request.method, 'INFO', f"Usuario {username} autenticado exitosamente")
        return jsonify(access_token=access_token, redirect=url_for('obtener_usuarios'), roles=roles), 200
    else:
        log_audit(username, request.method, 'ERROR', f"Intento fallido de autenticación para el usuario {username}")
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# Index
@app.route('/', methods=['GET'])
@limiter.limit("5 per minute")  # 5 requests per minute
def index():
    return render_template('login.html')

# Run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
    