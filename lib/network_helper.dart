library network_helper;

import 'dart:convert' as convert;
import 'package:flutter/foundation.dart';
import 'package:dio/dio.dart' as dioLib;
import 'package:cookie_jar/cookie_jar.dart';
import 'package:connectivity/connectivity.dart';
import 'package:ssh/ssh.dart';
import 'package:flutter/material.dart';
import 'dart:io';


_parseAndDecode(String response) {
  return convert.jsonDecode(response);
}
parseJson(String text) {
  return compute(_parseAndDecode, text);
}

class NetworkHelper {

  String urlWithTunnel;
  String urlWithoutTunnel;
  String urlInUse;
  List<String> safeWIFIs;
  String urlHost;
  String urlPath;
  String loginPath;

  Map _userInfo = {};
  int _tokenEXP = 0;


  SSHClient _sshClient;
  Map _sshInfo;

  Map _linkerTables = {};

  final dioLib.Dio dio = dioLib.Dio();
  final cj = CookieJar();

  /// NetworkHelper Constructor
  NetworkHelper(
      {@required this.urlHost, @required this.urlPath, this.loginPath, this.safeWIFIs}) {
    urlWithoutTunnel = 'https://$urlHost/$urlPath';

    dio.interceptors..add(dioLib.CookieManager(cj))..add(
        dioLib.LogInterceptor());
    (dio.transformer as dioLib.DefaultTransformer).jsonDecodeCallback =
        parseJson;
    dio.options.receiveTimeout = 100000;
    dio.options.connectTimeout = 100000;
  }


  /// if an SSH Tunnel with prot forwarding will be required,
  /// it will create the tunnel configs,
  /// this will not connect the tunnel.
  void setupSSHClient(String host, int port, String username,
      String passwordOrKey, int rPort, int lPort, String rHost) {
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
        (dio.httpClientAdapter as dioLib.DefaultHttpClientAdapter)
            .onHttpClientCreate = (client) {
          client.badCertificateCallback =
              (X509Certificate cert, String host, int port) => true;
          return client;
        };
      }
      dioLib.Response response = await dio.post('$urlInUse/$site', data: body,
          options: dioLib.Options(
            contentType: ContentType.parse('application/json'),));
      if (response.statusCode != 200) {
        print(response.statusCode);
        return null;
      }
      _tokenEXP = response.data['auth']['exp'];
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

  /// Here is the LinkerTable Stuff

  void addTable(Map map, String name) {
    _linkerTables[name] = map;
  }

  Map getTable(String name) {
    return _linkerTables[name];
  }

  Future<bool> getLinkerTables(BuildContext context, NetworkHelper networkHelper, Function navigate) async {
    var linkerTablesRaw = await networkHelper.sendPOSTRequest('linker_tables', {}, navigate);
    linkerTablesRaw.data['data'].forEach((key,value) => _linkerTables[key] = value);
    return true;
  }
}



