from ldap3 import *
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPOperationResult, LDAPExceptionError, LDAPException, \
    LDAPSocketOpenError
from ldap3.core.results import *
from ldap3.utils.dn import safe_dn
import os
from utils.tracecalls import decorator_logger
import logging

APP_ENV = os.getenv('APP_ENV')
if APP_ENV == 'dev':
    from conf.local_settings_dev import *
else:
    from conf.local_settings import *

logger = logging.getLogger(__name__)

"""
根据以下网站的说明: 
https://docs.microsoft.com/zh-cn/troubleshoot/windows/win32/change-windows-active-directory-user-password
密码存储在 unicodePwd 属性中的用户对象的 AD 和 LDS 数据库中 此属性可以在受限条件下写入, 但无法读取 只能修改属性;无法在对象创建时或由搜索查询时添加它
为了修改此属性, 客户端必须具有到服务器的 128 位传输层安全性 (TLS) /Secure Socket Layer (SSL) 连接 
使用 SSP 创建的会话密钥（使用 NTLM 或 Kerberos）的加密会话也可接受, 只要达到最小密钥长度
若要使用 TLS/SSL 实现此连接: 
    服务器必须拥有 128 位 RSA 连接的服务器证书
    客户端必须信任生成服务器证书 (CA) 证书颁发机构
    客户端和服务器都必须能够进行 128 位加密
    
unicodePwd 属性的语法为 octet-string;但是, 目录服务预期八进制字符串将包含 UNICODE 字符串 (, 因为属性的名称指示)  
这意味着在 LDAP 中传递的此属性的任何值都必须是 BER 编码的 UNICODE 字符串 (基本编码规则) 八进制字符串 
此外, UNICODE 字符串必须以引号开头和结尾, 这些引号不是所需密码的一部分

可通过两种方法修改 unicodePwd 属性 第一种操作类似于正常的 用户更改密码 操作 
在这种情况下, 修改请求必须同时包含删除和添加操作 删除操作必须包含当前密码, 并包含其周围的引号 
添加操作必须包含所需的新密码, 其周围必须有引号

修改此属性的第二种方法类似于管理员重置用户密码 为此, 客户端必须以具有修改其他用户密码的足够权限的用户进行绑定 
此修改请求应包含单个替换操作, 其中包含用引号括起的新所需密码 如果客户端具有足够的权限, 则无论旧密码是什么, 此密码都将变为新密码
"""


class AdOps(object):

    def __init__(self, auto_bind=True, use_ssl=LDAP_USE_SSL, port=LDAP_CONN_PORT, domain=LDAP_DOMAIN, user=LDAP_LOGIN_USER,
                 password=LDAP_LOGIN_USER_PWD,
                 authentication=NTLM):
        """
        AD连接器 authentication  [SIMPLE, ANONYMOUS, SASL, NTLM]
        :return:

        """
        self.use_ssl = use_ssl
        self.port = port
        # 如果doamin\\user中doamin部分被写成域名格式,  只提取DOMAIN部分
        self.domain = domain.split('.')[0] if domain is not None else None
        self.user = user
        self.password = password
        self.authentication = authentication
        self.auto_bind = auto_bind
        self.server = None
        self.conn = None

    def __server(self):
        if self.server is None:
            try:
                self.server = Server(host='%s' % LDAP_HOST, connect_timeout=1, use_ssl=self.use_ssl, port=self.port, get_info=ALL)
            except LDAPInvalidCredentialsResult as lic_e:
                return False, LDAPOperationResult("LDAPInvalidCredentialsResult: " + str(lic_e.message))
            except LDAPOperationResult as lo_e:
                return False, LDAPOperationResult("LDAPOperationResult: " + str(lo_e.message))
            except LDAPException as l_e:
                return False, LDAPException("LDAPException: " + str(l_e))

    def __conn(self):
        if self.conn is None:
            try:
                self.__server()
                self.conn = Connection(self.server,
                                       auto_bind=self.auto_bind, user=r'{}\{}'.format(self.domain, self.user),
                                       password=self.password,
                                       authentication=self.authentication,
                                       raise_exceptions=True)
            except LDAPInvalidCredentialsResult as lic_e:
                return False, LDAPOperationResult("LDAPInvalidCredentialsResult: " + str(lic_e.message))

            except LDAPOperationResult as lo_e:
                return False, LDAPOperationResult("LDAPOperationResult: " + str(lo_e.message))

            except LDAPException as l_e:
                return False, LDAPException("LDAPException: " + str(l_e))

    @decorator_logger(logger, log_head='AdOps', pretty=True, indent=2, verbose=1)
    def ad_auth_user(self, username, password):
        """
        验证账号
        :param username:
        :param password:
        :return: True or False
        """
        try:
            self.__server()
            c_auth = Connection(server=self.server, user=r'{}\{}'.format(self.domain, username), password=password,
                                auto_bind=True, raise_exceptions=True)
            c_auth.unbind()
            return True, '旧密码验证通过'
        except LDAPInvalidCredentialsResult as e:
            if '52e' in e.message:
                return False, u'账号或旧密码不正确!'
            elif '775' in e.message:
                return False, u'账号已锁定, 请自行扫码解锁!'
            elif '533' in e.message:
                return False, u'账号已禁用!'
            elif '525' in e.message:
                return False, u'账号不存在!'
            elif '532' in e.message:
                return False, u'密码己过期!'
            elif '701' in e.message:
                return False, u'账号己过期!'
            elif '773' in e.message:
                # 如果仅仅使用普通凭据来绑定ldap用途, 请返回False, 让用户通过其他途径修改密码后再来验证登陆
                # return False, '用户登陆前必须修改密码!'
                # 设置该账号下次登陆不需要更改密码, 再验证一次
                self.__conn()
                self.conn.search(search_base=BASE_DN, search_filter=SEARCH_FILTER.format(username),
                                 attributes=['pwdLastSet'])
                self.conn.modify(self.conn.entries[0].entry_dn, {'pwdLastSet': [(MODIFY_REPLACE, ['-1'])]})
                return True, self.ad_auth_user(username, password)
            else:
                return False, u'旧密码认证失败, 请确认账号的旧密码是否正确或使用重置密码功能'
        except LDAPException as e:
            return False, "连接Ldap失败, 报错如下: {}".format(e)

    def ad_ensure_user_by_account(self, username):
        """
        通过username查询某个用户是否在AD中
        :param username:
        :return: True or False
        """
        try:
            self.__conn()
            return True, self.conn.search(BASE_DN, SEARCH_FILTER.format(username), attributes=['sAMAccountName'])
        except IndexError:
            return False, "🥹错误: 在查询用户是否在域中, 未检索到任何信息, 请与联系IT部门处理!"
        except Exception as e:
            return False, "😱非预期错误: {}".format(e)
        
    # 新增函数, 用于企微邮箱转AD域用户名称  
 
    # 新增时间: 2023-08-06  
    # 新增人: 邢传真 
    # 原因: 原项目代码不能适配公司系统, 企微邮箱前缀和域用户不一定对应
    def ad_get_get_sAMAccountName_by_email(self, email):
        """
        通过用户的的企业微信邮箱得到用户AD域中的sAMAccountName属性(域账号)
        :param email: 用户企微邮箱的地址
        :return: tuple(bool, str or None) 
        """
        try:
            # 如果传进来的不是邮箱, 就不转换
            if "@" in email:
                self.__conn()
                self.conn.search(BASE_DN, "(mail=" + email + ")", attributes=['sAMAccountName'])
                return True, self.conn.entries[0]['sAMAccountName']
            else:
                return True, email
        except Exception as e:  
            logger.error("self.conn.search(BASE_DN, {}, attributes=['sAMAccountName'])".format(SEARCH_FILTER.format(email)))
            return False, "😱非预期错误: {}".format(e)
        
    @decorator_logger(logger, log_head='AdOps', pretty=True, indent=2, verbose=1)
    def ad_get_user_dn_by_account(self, username):
        """
        通过username查询某个用户的完整DN
        :param username:
        :return: DN
        """
        try:
            self.__conn()
            self.conn.search(BASE_DN, SEARCH_FILTER.format(username),
                             attributes=['distinguishedName'])
            return True, str(self.conn.entries[0]['distinguishedName'])
        except IndexError:
            logger.error("AdOps Exception: Connect.search未能检索到任何信息, 当前账号可能被排除在<SEARCH_FILTER>之外, 请联系管理员处理2")
            logger.error("self.conn.search(BASE_DN, {}, attributes=['distinguishedName'])".format(SEARCH_FILTER.format(username)))
            return False, "🥹错误: 在查询用户完整DN时, 未检索到任何信息, 请与联系IT部门处理!"
        except Exception as e:
            logger.error("AdOps Exception: {}".format(e))
            return False, "😱非预期错误: {}".format(e)

    @decorator_logger(logger, log_head='AdOps', pretty=True, indent=2, verbose=1)
    def ad_get_user_status_by_account(self, username):
        """
        通过username查询某个用户的账号状态
        :param username:
        :return: user_account_control code
        """
        try:
            self.__conn()
            self.conn.search(BASE_DN, SEARCH_FILTER.format(username), attributes=['userAccountControl'])
            return True, self.conn.entries[0]['userAccountControl']
        except IndexError:
            logger.error("AdOps Exception: Connect.search未能检索到任何信息, 当前账号可能被排除在<SEARCH_FILTER>之外, 请联系管理员处理4")
            logger.error("self.conn.search({}, {}, attributes=['userAccountControl'])".format(BASE_DN, SEARCH_FILTER.format(username)))
            logger.info("self.conn.entries -- {}".format(self.conn.entries))
            return False, "🥹错误: 在查询用户账号状态时, 未检索到任何信息, 请与联系IT部门处理!"
        except Exception as e:
            logger.error("AdOps Exception: {}".format(e))
            return False, "😱非预期错误: {}".format(e)

    @decorator_logger(logger, log_head='AdOps', pretty=True, indent=2, verbose=1)
    def ad_unlock_user_by_account(self, username):
        """
        通过username解锁某个用户
        :param username:
        :return:
        """
        _status, user_dn = self.ad_get_user_dn_by_account(username)
        if _status:
            try:
                return True, self.conn.extend.microsoft.unlock_account(user='%s' % user_dn)
            except IndexError:
                return False, "🥹错误: 在解锁用户时, 未检索到任何信息, 请与联系IT部门处理!"
            except Exception as e:
                logger.error("AdOps Exception: {}".format(e))
                return False, "😱非预期错误: {}".format(e)
        else:
            return False, user_dn

    @decorator_logger(logger, log_head='AdOps', pretty=True, indent=2, verbose=1)
    def ad_reset_user_pwd_by_account(self, username, new_password):
        """
        重置某个用户的密码
        :param username:
        :return:
        """
        _status, user_dn = self.ad_get_user_dn_by_account(username)
        if _status:
            if self.conn.check_names:
                user_dn = safe_dn(user_dn)
            encoded_new_password = ('"%s"' % new_password).encode('utf-16-le')
            result = self.conn.modify(user_dn,
                                      {'unicodePwd': [(MODIFY_REPLACE, [encoded_new_password])]},
                                      )
            if not self.conn.strategy.sync:
                _, result = self.conn.get_response(result)
            else:
                if self.conn.strategy.thread_safe:
                    _, result, _, _ = result
                else:
                    result = self.conn.result

            # change successful, returns True
            if result['result'] == RESULT_SUCCESS:
                return True, '🎉密码己修改成功, 请妥善保管!'

            # change was not successful, raises exception if raise_exception = True in connection or returns the operation result, error code is in result['result']
            if self.conn.raise_exceptions:
                from ldap3.core.exceptions import LDAPOperationResult
                _msg = LDAPOperationResult(result=result['result'], description=result['description'], dn=result['dn'],
                                           message=result['message'],
                                           response_type=result['type'])
                return False, _msg
            return False, result['result']
        else:
            return False, user_dn

    @decorator_logger(logger, log_head='AdOps', pretty=True, indent=2, verbose=1)
    def ad_get_user_locked_status_by_account(self, username):
        """
        通过username获取某个用户账号是否被锁定
        :param username:
        :return: 如果结果是1601-01-01说明账号未锁定, 返回0
        """
        try:
            self.__conn()
            self.conn.search(BASE_DN, SEARCH_FILTER.format(username),
                             attributes=['lockoutTime'])
            locked_status = self.conn.entries[0]['lockoutTime']
            if '1601-01-01' in str(locked_status):
                return True, 'unlocked'
            else:
                return False, locked_status
        except IndexError:
            # return False, "AdOps Exception: Connect.search未能检索到任何信息, 当前账号可能被排除在<SEARCH_FILTER>之外, 请联系管理员处理7"
            return False, "🥹错误: 在检查用户账号是否被锁定时, 未检索到任何信息, 请与联系IT部门处理!"
        except Exception as e:
            return False, "😱非预期错误: {}".format(e)
