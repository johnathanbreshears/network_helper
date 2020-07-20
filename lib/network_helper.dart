library network_helper;

import 'dart:convert' as convert;
import 'package:flutter/foundation.dart';
import 'package:dio/dio.dart' as dioLib;
import 'package:dio_cookie_manager/dio_cookie_manager.dart';
import 'package:cookie_jar/cookie_jar.dart';
import 'package:connectivity/connectivity.dart';
import 'package:ssh/ssh.dart';
import 'package:flutter/material.dart';
import 'dart:io';
import 'package:path_provider/path_provider.dart';
import 'package:dio/adapter.dart';

/// two small helper functions that are used in the Constructor under
/// dioLib.DefaultTransformer.
_parseAndDecode(String response) {
  return convert.jsonDecode(response);
}
parseJson(String text) {
  return compute(_parseAndDecode, text);
}

class NetworkHelper {


  /// variable initialize and declare
  String urlWithTunnel, urlWithoutTunnel, urlInUse, urlHost, urlPath, loginPath, _cookieString;
  int _tokenEXP = 0;
  List<String> safeWIFIs;
  Map _sshInfo;
  Map _userInfo = {};
  Map _linkerTables = {};
  SSHClient _sshClient;
  File _cookieFile;
  final dioLib.Dio dio = dioLib.Dio();
  var cj = CookieJar();


  /// NetworkHelper Constructor
  NetworkHelper({@required this.urlHost, @required this.urlPath, this.loginPath, this.safeWIFIs}) {

    urlWithoutTunnel = 'https://$urlHost/$urlPath';

    dio.interceptors..add(CookieManager(cj))..add(dioLib.LogInterceptor());
    (dio.transformer as dioLib.DefaultTransformer).jsonDecodeCallback = parseJson;
    dio.options.receiveTimeout = 100000;
    dio.options.connectTimeout = 100000;
  }


  /// Both _localPath and _localCookieDirectory are used in _cookieFileExists(),
  /// this uses path_provider.dart to get a local directory and create the /cookies
  /// directory in that directory.
  Future<String> get _localPath async {
    final directory = await getApplicationDocumentsDirectory();
    return directory.path;
  }
  Future<Directory> get _localCookieDirectory async {
    final path = await _localPath;
    final Directory dir = new Directory('$path/cookies');
    await dir.create();
    return dir;
  }

  /// returns true if the local jsh_cookie.txt exists,
  /// and reads the cookie writen there and saves it as _cookieString
  /// returns false if the file does not exists, then creates that file.
  Future<bool> _cookieFileExists() async {
    var pathToDir = await _localCookieDirectory;
    String path = '${pathToDir.path}/jsh_cookie.txt';
    _cookieFile = File(path);
    if (await _cookieFile.exists()) {
      print('The File exists');
      _cookieString = await _cookieFile.readAsString();
      return true;
    }
    _cookieFile.create();
    return false;
  }

  /// Takes Response and get the cookie from it
  /// then returns the cookie String
  String _setCookieString(dioLib.Response response) {
    List<String> cookieList = response.headers[HttpHeaders.setCookieHeader];
    if (cookieList != null) {
      List<Cookie> cookies = cookieList.map((str) => Cookie.fromSetCookieValue(str)).toList();
      return 'jwtToken=${cookies[0].value}';
    }
    print('CookieString is null');
    return null;
  }

  /// Checks if we have a valid JWT Token
  /// first it checks is there is even a file on devise with cookie
  /// then does a backend call using /chklogin
  /// if backend server says cookie is still valid,
  /// get user and tokenEXP from the response
  /// sets new cookie in the header
  Future<bool> checkValidJWT() async {
    if (!(await _cookieFileExists())) {
      return false;
    }
    await _connectToTunnelIfNeeded();
    try {
      dio.options.headers['cookie'] = _cookieString;
      if (Platform.isAndroid) {
        (dio.httpClientAdapter as DefaultHttpClientAdapter)
            .onHttpClientCreate = (client) {
          client.badCertificateCallback =
              (X509Certificate cert, String host, int port) => true;
          return client;
        };
      }
      print('Here is the urlInUse: $urlInUse');
      dioLib.Response response = await dio.post('$urlInUse/chklogin', data: '', options: dioLib.Options(contentType: ContentType.parse('application/json').toString(),));
      if (response.statusCode != 200) {
        print(response.statusCode);
        return false;
      }
      _userInfo = response.data['auth']['sub'];
      _tokenEXP = response.data['auth']['exp'];
      _cookieString = _setCookieString(response);
      if (_cookieString == null) {
        return false;
      }
      dio.options.headers['cookie'] = _cookieString;
      return true;
    } catch (e) {
      print(e);
      return false;
    }
  }

  /// Saves the current cookieString to the cookieFile
  void saveCookieToFile() {
    _cookieFile.writeAsStringSync(_cookieString);
  }

  /// if an SSH Tunnel with prot forwarding will be required,
  /// it will create the tunnel configs,
  /// this will not connect the tunnel.
  void setupSSHClient(String host, int port, String username, String passwordOrKey, int rPort, int lPort, String rHost) {
    _sshInfo = {
      'host': host,
      'port': port,
      'username': username,
      'passwordOrKey': passwordOrKey,
      'rPort': rPort,
      'lPort': lPort,
      'rHost': rHost
    };
    _sshClient = SSHClient(host: _sshInfo['host'],
        port: _sshInfo['port'],
        username: _sshInfo['username'],
        passwordOrKey: _sshInfo['passwordOrKey']);
  }

  /// returns a true is the user is currently on a approved WIFI based on the
  /// safeWIFIs list, if not returns false
  Future<bool> _checkIfNetworkSafe() async {
    var connectivityResult = await (Connectivity().checkConnectivity());
    var wifiName = await (Connectivity().getWifiName());
    if (connectivityResult == ConnectivityResult.mobile) {
      // I am connected to a mobile network.
      return false;
    } else if (connectivityResult == ConnectivityResult.wifi) {
      for (String currentWIFI in safeWIFIs) {
        if (currentWIFI == wifiName)
          return true;
      }
      return false;
    }
    return false;
  }

  /// Checks if user in on a safe network using the _checkIfNetworkSafe() method
  /// if safe makes sure tunnel is not connected, if is then disconnects tunnel
  /// if not safe checks if tunnel is created if not, creates and connect tunnel
  Future<void> _connectToTunnelIfNeeded() async {
    try {
      bool onSafeWIFI = await _checkIfNetworkSafe();
      if (onSafeWIFI) {
        print("You are on a safe WIFI, no tunnel needed");
        urlInUse = urlWithoutTunnel;
        if (_sshClient != null) {
          if (await _sshClient.isConnected()) {
            print("Disconnecting SSH Tunnel");
            _sshClient.disconnect();
          }
        }
      } else {
        if (_sshClient == null) {
          print("Create SSH Tunnel");
          await _connectToTunnel();
        } else {
          urlInUse = urlWithTunnel;
          if (!await _sshClient.isConnected()) {
            print("Reconnecting to SSH Tunnel");
            await _connectToTunnel();
          }
        }
      }
    } catch (e) {
      print("Error is networking.checkConnectionNeeded: $e");
    }
  }

  /// Connects the sshClient using configs set up in the setupSSHClient() method,
  /// uses the SSHClient.portForwardL() method to setup port forwarding and
  /// returns the port to use with the url
  Future<void> _connectToTunnel() async {
    if (_sshClient == null) {
      print('Did not provide SSH CONFIGS!');
      return null;
    }
    try {
      await _sshClient.connect();
      var assignedPort = await _sshClient.portForwardL(
          _sshInfo['rPort'], _sshInfo['lPort'], _sshInfo['rHost']);
      urlWithTunnel = 'https://127.0.0.1:$assignedPort/$urlPath';
      urlInUse = urlWithTunnel;
    } catch (e) {
      print('\nError in connectToTunnel Method: $e');
    }
  }

  /// checks if token is expired, if it is expired then returns true
  bool _tokenIsExpired() {
    if ((DateTime
        .now()
        .toUtc()
        .millisecondsSinceEpoch / 1000) < _tokenEXP) {
      return false;
    }
    return true;
  }

  /// sends a Post request to using the urlInUse
  /// returns the dioLib.Response.data
  Future sendPOSTRequest(String site, Map body, Function navigate) async {
    await _connectToTunnelIfNeeded();
    if (site != loginPath && _tokenIsExpired()) {
      await navigate();
    }
    try {
      if (Platform.isAndroid) {
        (dio.httpClientAdapter as DefaultHttpClientAdapter)
            .onHttpClientCreate = (client) {
          client.badCertificateCallback =
              (X509Certificate cert, String host, int port) => true;
          return client;
        };
      }
      dioLib.Response response = await dio.post('$urlInUse/$site', data: body,
          options: dioLib.Options(
            contentType: ContentType.parse('application/json').toString(),));
      if (response.statusCode != 200) {
        print(response.statusCode);
        return null;
      }
      _tokenEXP = response.data['auth']['exp'];
      _cookieString = _setCookieString(response);
      return response;
    } catch (e) {
      print(e);
    }
  }

  /// takes a username and password, calls the sendPOSTRequest() with that as
  /// the body, if the login status is successful returns true
  /// if for any reason the NetworkHelper can not log the user in the the server
  /// will return false.
  /// this will also set the Cookies/JWTToken that it gets from the backend
  /// server into the CookieJar cj
  Future<bool> login(String username, String password) async {
    try {
      cj.deleteAll();
      var statusOfLogin = await sendPOSTRequest(
          'login', {"password": password, "username": username}, null);
      if (statusOfLogin.data['status'] == 'SUCCESS') {
        _userInfo = statusOfLogin.data['auth']['sub'];
        _tokenEXP = statusOfLogin.data['auth']['exp'];
        List<String> cookieString = statusOfLogin.headers[HttpHeaders
            .setCookieHeader];
        if (cookieString != null) {
          List<Cookie> cookies = cookieString.map((str) =>
              Cookie.fromSetCookieValue(str)).toList();
          dio.options.headers['cookie'] = 'jwtToken=${cookies[0].value}';
          return true;
        } else {
          print('CookieString is null');
          return false;
        }
      } else {
        print('Incorrect username or password');
        return false;
      }
    } catch (e) {
      String error = e.toString();
      if (error.startsWith(
          'DioError [DioErrorType.DEFAULT]: HttpException: , uri =')) {
        print('normal error');
        return login(username, password);
      } else {
        print('this is the error: ($e)');
        return false;
      }
    }
  }

  /// returns the user Info
  Map getUserInfo() {
    return _userInfo;
  }

  /// takes a given name and,
  /// returns the _linkerTables List[given name]
  Map getTable(String name) {
    return _linkerTables[name];
  }

  /// makes a sendPostRequest with the linkerAddress and then adds the whole
  /// map(from the response.data['data']) to the _linkerTables List
  Future<bool> getLinkerTables(String linkerAddress, Function navigate) async {
    var linkerTablesRaw = await sendPOSTRequest(linkerAddress, {}, navigate);
    linkerTablesRaw.data['data'].forEach((key,value) => _linkerTables[key] = value);
    return true;
  }
}

