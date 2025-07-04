<h2 align="center">
  <p align="center"><img width=30% src="https://raw.githubusercontent.com/kha7iq/kc-ssh-pam/master/.github/img/logo.png"></p>
</h2>
<p align="center">
  <img alt="GitHub Build Status" src="https://img.shields.io/github/actions/workflow/status/kha7iq/kc-ssh-pam/build.yml?label=Build">
   <a href="https://github.com/kha7iq/kc-ssh-pam/releases">
   <img alt="Release" src="https://img.shields.io/github/v/release/kha7iq/kc-ssh-pam?label=Release">
   <a href="https://goreportcard.com/report/github.com/kha7iq/kc-ssh-pam">
   <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/kha7iq/kc-ssh-pam">
   <a href="#">
   <img alt="GitHub go.mod Go version" src="https://img.shields.io/github/go-mod/go-version/kha7iq/kc-ssh-pam">
   <a href="https://github.com/kha7iq/kc-ssh-pam/issues">
   <img alt="GitHub issues" src="https://img.shields.io/github/issues/kha7iq/kc-ssh-pam?style=flat-square&logo=github&logoColor=white">
   <a href="https://github.com/kha7iq/kc-ssh-pam/blob/master/LICENSE.md">
   <img alt="License" src="https://img.shields.io/github/license/kha7iq/kc-ssh-pam">
</p>

<p align="center">
  <a href="#install">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#contributers ">Contributers </a> •
  <a href="#contributing">Contributing</a> •
</p>

# Keycloak SSH PAM

**kc-ssh-pam** designed to streamline the process of user authentication and enable users to access Linux systems through SSH. The program integrates with Keycloak to obtain a password grant token based on the user's login credentials, including their username and password. If two-factor authentication is enabled for the user, the program supports OTP code as well.

Once the password grant token is obtained, the program verifies it and passes the necessary parameters so that the user can be authenticated via SSH and access the Linux systems.

## Install

<details>
    <summary>DEB & RPM</summary>

```bash
# DEB
sudo dpkg -i kc-ssh-pam_amd64.deb

# RPM
sudo rpm -i kc-ssh-pam_amd64.rpm

```
</details>


<details>
    <summary>Manual</summary>

```bash
# Chose desired version
export KC_SSH_PAM_VERSION="0.1.2"
wget -q https://github.com/kha7iq/kc-ssh-pam/releases/download/v${KC_SSH_PAM_VERSION}/kc-ssh-pam_linux_amd64.tar.gz && \
tar -xf kc-ssh-pam_linux_amd64.tar.gz && \
chmod +x kc-ssh-pam && \
sudo mkdir -p /opt/kc-ssh-pam && \
sudo mv kc-ssh-pam config.toml /opt/kc-ssh-pam
```
</details>


## Usage
```bash
❯ kc-ssh-pam --help
Usage: kc-ssh-pam USERNAME PASSWORD/[OTP]

Generates a password grant token from Keycloak for the given user.

Options:
  -h, --help              Show this help message and exit
  -v, --version           Show version information
  -c                      Set configuration file path

Notes:
  For the program to function properly, it needs to locate a configuration file called 'config.toml'.
  The program will search for this file in the current directory, '/opt/kc-ssh-pam' and '$HOME/.config/config.toml',
  in that specific order. You can also set a custom path by specifying KC_SSH_CONFIG variable or -c flag which takes prefrence.

  In addition to defaults, all configuration parameters can also be provided through environment variables.

  KC_SSH_CONFIG KC_SSH_REALM KC_SSH_ENDPOINT KC_SSH_CLIENTID KC_SSH_CLIENTSECRET KC_SSH_CLIENTSCOPE
  
  To use the program, you must create a client in Keycloak and provide the following 
  information in the configuration file: realm, endpoint, client ID, client secret, and 
  client scope is optional.

Arguments:
  USERNAME                The username of the user is taken from $PAM_USER environment variable
  PASSWORD                The password of the user is taken from stdIn
  OTP                     (Optional) The OTP code if two-factor authentication is enabled i.e (password/otp)

  EXAMPLE                 (With otp): echo testpass/717912 | kc-ssh-pam (Only Password): echo testpass | kc-ssh-pam

```

## Configuration
  For the program to function properly, it needs to locate a configuration file called `config.toml`.
  
  The program will search for this file in the follwoing order..
  1. If a config path is specified using the `-c` flag, it will override any other defined options.
  2. Verify the existence of the KC_SSH_CONFIG variable; if it's defined, use the location specified within it.
  3. The working directory where the program is being executed from.
  4. Default install location `/opt/kc-ssh-pam/`
  5. `$HOME/.config/`
  
  
> [!IMPORTANT]  
> For proper operation, ensure that SeLinux is configured in Permissive mode.
  
`config.toml`
  ```
realm = "ssh-demo"
endpoint = "https://keycloak.example.com"
clientid = "keycloak-client-id"
clientsecret = "MIKEcHObWmI3V3pF1hcSqC9KEILfLN"
clientscope = "openid"
clientrole = "keycloak-client-role"
  ```
* Edit `/etc/pam.d/sshd` and add the following at the top of file
```bash
auth [success=done default=die] pam_exec.so expose_authtok  quiet  log=/var/log/kc-ssh-pam.log  /opt/kc-ssh-pam/kc-ssh-pam
```
- User is not automatically created during login, so a local user must be present on the system before hand.

Restart sshd service
```bash
sudo systemctl restart sshd
```

### Keycloak Client Creation
```bash
Step 1: Log in to the Keycloak Administration Console.

Step 2: Select the realm for which you want to create the client.

Step 3: Click on "Clients" from the left-hand menu, then click the "Create client" button.

Step 4: In the "Client type" field, select "openid-connect".

Step 5: In the "Client ID" field, enter "ssh-login".

Step 6: Set "Client authentication" to ON.

Step 7: Set "Standard Flow Enabled" to ON.

Step 8: Set "Direct Access Grants" to ON.

Step 9: In the "Redirect URIs" field, enter "urn:ietf:wg:oauth:2.0:oob".

Step 10: Click the "Save" button to create the client.
```

### Create a Client Role
```bash
Step 1: Go to the "Clients" page in the Keycloak Administration Console.

Step 2: Select the "ssh-login" client from the list.

Step 3: Go to the "Roles" tab.

Step 4: Click the "Create role" button.

Step 5: Set the Role name to "ssh-pc1".

Step 6: Click the "Save" button to create the client role.
```

### Assign Role to a User Group
```bash
Step 1: Go to the "Groups" page in the Keycloak Administration Console.

Step 2: Select the group to assign the client role to.

Step 3: Go to the "Role mapping" tab.

Step 4: Click the "Assign role" button.

Step 5: Select the client role "ssh-pc1".

Step 6: Click the "Assign" button to assign the client role.
```

### Get Client Credentials
```bash
Step 1: Go to the "Clients" page in the Keycloak Administration Console.

Step 2: Select the "ssh-login" client from the list.

Step 3: Click on the "Credentials" tab.

Step 4: The client secret is displayed under the "Client Secret" section.
```

## Contributers
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="left" valign="top" width="14.28%"><a href="https://github.com/sradigan"><img src="https://gitlab.com/uploads/-/system/user/avatar/2473327/avatar.png" width="100px;" alt="Sean Radigan "/><br /><sub><b>Sean Radigan </b></sub></a><br /><a href="https://github.com/kha7iq/kc-ssh-pam/pull/6" title="Documentation">📖</a> <a href="https://github.com/kha7iq/kc-ssh-pam/pull/6" title="Code">💻</a></td>
    </tr>
  </tbody>
</table>


## Contributing

Contributions, issues and feature requests are welcome!<br/>Feel free to check
[issues page](https://github.com/kha7iq/kc-ssh-pam/issues). You can also take a look
at the [contributing guide](https://github.com/kha7iq/kc-ssh-pam/blob/master/CONTRIBUTING.md).
