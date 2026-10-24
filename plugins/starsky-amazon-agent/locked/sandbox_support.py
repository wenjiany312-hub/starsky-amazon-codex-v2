"""Installer-owned Codex permission setup and stable, read-only KB dispatch.

Normal unlock never calls setup. No sandbox/approval mode is modified here.
"""
from pathlib import Path
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import uuid

KINDS={'ads-kb':'ads_knowledge_base','selection-kb':'selection_knowledge_base','promotion-kb':'promotion_knowledge_base'}

# Import names for the existing, version-locked installer requirements.
RUNTIME_IMPORTS=('cryptography','yaml','openpyxl','PIL','bs4','soupsieve','requests',
                 'Crypto','mcp','playwright','numpy','pandas','pymupdf','jsonschema',
                 'urllib3','cv2','rapidocr','onnxruntime')
FILE_MANIFEST='runtime-files.json'


class RuntimeCheckError(ValueError):
    """An actionable startup failure safe to show on the blocked startup card."""


def check_dependencies(python, *, modules=RUNTIME_IMPORTS):
    """Actually import each dependency in the designated interpreter, not this one."""
    program='''import importlib,json,sys
missing=[]
for module in json.loads(sys.argv[1]):
    try: importlib.import_module(module)
    except Exception: missing.append(module)
print(json.dumps(missing))
'''
    try:
        result=subprocess.run([str(python),'-B','-c',program,json.dumps(list(modules))],
                              capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60,
                              env={**os.environ,'PYTHONUTF8':'1','PYTHONDONTWRITEBYTECODE':'1'},
                              creationflags=0x08000000 if os.name=='nt' else 0)
        missing=json.loads(result.stdout.strip().splitlines()[-1]) if result.returncode==0 else list(modules)
        if not isinstance(missing,list):raise ValueError('invalid dependency response')
    except (OSError,ValueError,IndexError,subprocess.SubprocessError):
        raise RuntimeCheckError('专用 Python 自检未完成；请运行安装包里的「安装与更新」修复。') from None
    if missing:
        error=RuntimeCheckError('专用运行环境缺少或无法导入 '+ '、'.join(missing)+'；请运行安装包里的「安装与更新」修复。')
        error.missing=list(missing)  # 解锁脚本据此向用户说明缺什么，并自动准备新环境
        raise error
    return {'checked_modules':list(modules)}


def check_files(folder, *, expected=None, required=False):
    """Detect native-copy omissions; unrelated user files are never deleted/rejected."""
    folder=Path(folder);manifest=folder/FILE_MANIFEST
    if not manifest.is_file() and expected is None and not required:return {'applicable':False}
    try:
        actual=json.loads(manifest.read_text(encoding='utf-8-sig'))
        if expected is not None and actual!=expected:raise ValueError('manifest mismatch')
        files=actual['files']
        if actual.get('schema')!=1 or actual['file_count']!=len(files) or len(set(files))!=len(files):
            raise ValueError('manifest count mismatch')
        missing=[]
        for name in files:
            path=(folder/name).resolve()
            if not path.is_relative_to(folder.resolve()):raise ValueError('invalid manifest path')
            if not path.is_file():missing.append(name)
    except (OSError,ValueError,KeyError,TypeError):
        raise RuntimeCheckError('插件文件清单缺失或不一致；请运行安装包里的「安装与更新」修复。') from None
    if missing:
        raise RuntimeCheckError('插件缺少 '+str(len(missing))+' 个文件（'+missing[0]+'）；请运行安装包里的「安装与更新」修复。')
    return {'verified_files':len(files),'manifest':actual}


def array_end(text,start):
    depth=0;quote=None;triple=False;escaped=False;comment=False;i=start
    while i<len(text):
        ch=text[i]
        if comment:
            if ch=='\n':comment=False
        elif quote:
            if escaped:escaped=False
            elif quote=='"' and ch=='\\':escaped=True
            elif triple and text[i:i+3]==quote*3:quote=None;triple=False;i+=2
            elif not triple and ch==quote:quote=None
        elif ch=='#':comment=True
        elif ch in ('"',"'"):
            quote=ch;triple=text[i:i+3]==ch*3
            if triple:i+=2
        elif ch=='[':depth+=1
        elif ch==']':
            depth-=1
            if depth==0:return i
        i+=1
    raise ValueError('Codex 可写目录数组不完整，原配置未修改。')


def validate_config(text):
    parsed=tomllib.loads(text)
    if parsed.get('permissions') and not parsed.get('default_permissions'):
        raise ValueError('Codex 配置定义了 permissions，但缺少顶层 default_permissions；未写入。')
    selected=parsed.get('default_permissions')
    if selected and not selected.startswith(':') and selected not in parsed.get('permissions',{}):
        raise ValueError('Codex default_permissions 指向不存在的权限档；未写入。')
    for profile in parsed.get('profiles',{}).values():
        ref=profile.get('default_permissions')
        if ref and not ref.startswith(':') and ref not in parsed.get('permissions',{}):
            raise ValueError('用户运行配置引用了不存在的权限档；未写入。')
    return parsed


def write_config(config,before,updated):
    validate_config(updated)
    config.parent.mkdir(parents=True,exist_ok=True)
    if config.is_symlink():raise ValueError('Codex 配置是符号链接，原文件保留，请人工核对。')
    if config.exists() and config.read_bytes()!=before:raise ValueError('Codex 配置正在变化，请稍后重试。')
    backup=config.with_name(config.name+'.bak-starsky-permissions-'+uuid.uuid4().hex)
    if config.exists():shutil.copy2(config,backup)
    temporary=config.with_name(config.name+'.'+uuid.uuid4().hex+'.tmp')
    encoded=updated.encode('utf-8')
    try:
        temporary.write_bytes(encoded)
        if os.name!='nt':temporary.chmod(0o600)
        os.replace(temporary,config)
        try:
            actual=config.read_bytes()
            if actual!=encoded:raise ValueError('Codex 配置回读发生变化，请核对备份。')
            validate_config(actual.decode('utf-8-sig'))
        except Exception:
            # Do not overwrite an unrelated concurrent edit while recovering.
            if config.read_bytes()==encoded:
                if before:
                    temporary.write_bytes(before)
                    if os.name!='nt':temporary.chmod(0o600)
                    os.replace(temporary,config)
                else:config.unlink()
            raise
    finally:temporary.unlink(missing_ok=True)
    return str(backup) if before else None


def repair_invalid_profile(config,root):
    """Remove ONLY the exact unused profile emitted by 3.0.19 without a default.

    User-modified profiles and valid configurations are never removed. A backup
    precedes replacement. No global default, approval or network setting is set.
    """
    config,root=Path(config),Path(root).resolve()
    if not config.is_file():return {'changed':False}
    before=config.read_bytes();text=before.decode('utf-8-sig');parsed=tomllib.loads(text)
    if parsed.get('default_permissions'):return {'changed':False}
    profiles=parsed.get('permissions',{})
    names=[name for name,profile in profiles.items() if re.fullmatch(r'starsky-workspace(?:-[0-9a-f]{8})?',name)
           and profile=={'extends':':workspace','filesystem':{root.as_posix():'write'}}]
    if not names:return {'changed':False}
    references={profile.get('default_permissions') for profile in parsed.get('profiles',{}).values()}
    if references.intersection(names):
        raise ValueError('星空权限档已被用户运行配置引用，不能自动删除；原配置保留，请联系作者核对。')
    headers=list(re.finditer(r'(?m)^[ \t]*\[[^\r\n]+\][ \t]*(?:#[^\r\n]*)?(?:\r?\n|$)',text))
    spans=[]
    for name in names:
        owned=[]
        for index,header in enumerate(headers):
            try:
                sample=tomllib.loads(header.group(0)+'\n__starsky_marker__=true\n')['permissions'][name]
                kind='profile' if sample.get('__starsky_marker__') else 'filesystem' if sample.get('filesystem',{}).get('__starsky_marker__') else None
            except (ValueError,KeyError,TypeError):continue
            if not kind:continue
            end=headers[index+1].start() if index+1<len(headers) else len(text)
            lines=list(re.finditer(r'[^\r\n]*(?:\r?\n|$)',text[header.end():end]))
            actual=[line for line in lines if line.group().strip() and not line.group().lstrip().startswith('#')]
            if len(actual)!=1:continue
            line=actual[0]
            try:value=tomllib.loads(line.group())
            except ValueError:continue
            wanted={'extends':':workspace'} if kind=='profile' else {root.as_posix():'write'}
            if value!=wanted:continue
            owned.append((header.start(),header.end()))
            owned.append((header.end()+line.start(),header.end()+line.end()))
        if len(owned)==4:spans.extend(owned)
    if not spans:return {'changed':False}
    updated=text
    for lo,hi in sorted(spans,reverse=True):updated=updated[:lo]+updated[hi:]
    validate_config(updated)
    return {'changed':True,'backup':write_config(config,before,updated),'removed_lines':len(spans),'default_changed':False}


def named_root(config,root,before,text,parsed,selected):
    profiles=parsed.get('permissions',{})
    result={'changed':False,'read_only':False,'root':root.as_posix(),'restart_required':True,
            'configuration':'permissions','profile':selected,'selection_required':False}
    def writable(name,seen=()):
        if name==':workspace':return True
        if name==':read-only':return False
        if name in seen or name not in profiles:raise ValueError('权限档继承关系不完整，原配置未修改。')
        profile=profiles[name]
        return any(v=='write' or isinstance(v,dict) and v.get('.')=='write' for v in profile.get('filesystem',{}).values()) or bool(profile.get('extends') and writable(profile['extends'],(*seen,name)))
    if selected==':danger-full-access':return result
    if not writable(selected):return {**result,'read_only':True}
    import copy
    expected=copy.deepcopy(parsed)
    path=root.as_posix();encoded=json.dumps(path,ensure_ascii=False)
    if selected.startswith(':'):
        # No unused named profiles: current clients reject them without a global
        # default. Never change that global default just to install a plugin.
        return {**result,'permission_request_required':True,'profile_created':False}
    else:
        filesystem=profiles[selected].get('filesystem',{})
        if filesystem.get(path)=='write':return result
        if path in filesystem:return {**result,'read_only':True,'explicit_path_restriction':True}
        parts=['permissions',selected,'filesystem']
        headers=list(re.finditer(r'(?m)^[ \t]*(\[[^\r\n]+\])[ \t\r]*(?:#[^\r\n]*)?$',text))
        target=None
        for header in headers:
            try:
                sample=tomllib.loads(header.group(1)+'\n__starsky_marker__=true\n')
                for key in parts:sample=sample[key]
                if sample.get('__starsky_marker__'):target=header;break
            except (ValueError,KeyError,TypeError):continue
        if target:
            end=next((h.start() for h in headers if h.start()>target.start()),len(text))
            updated=text[:end].rstrip()+'\n'+encoded+' = "write"\n\n'+text[end:]
        else:
            if filesystem:raise ValueError('权限档使用内联文件规则，无法安全追加；原配置保留。')
            updated=text.rstrip()+'\n\n[permissions.'+json.dumps(selected)+'.filesystem]\n'+encoded+' = "write"\n'
        expected['permissions'][selected].setdefault('filesystem',{})[path]='write'
    if tomllib.loads(updated)!=expected:raise ValueError('权限档修改触及其他设置，已取消。')
    return {**result,'changed':True,'backup':write_config(config,before,updated)}


def register_root(config,root,*,native_profiles=False):
    config,root=Path(config),Path(root).resolve()
    repaired=repair_invalid_profile(config,root)
    before=config.read_bytes() if config.exists() else b''
    text=before.decode('utf-8-sig');parsed=tomllib.loads(text)
    sandbox=parsed.get('sandbox_workspace_write',{})
    roots=sandbox.get('writable_roots',[])
    if not isinstance(roots,list) or not all(isinstance(v,str) for v in roots):
        raise ValueError('Codex writable_roots 不是路径列表，原配置未修改。')
    profile=parsed.get('profiles',{}).get(parsed.get('profile',''),{})
    mode=profile.get('sandbox_mode',parsed.get('sandbox_mode'))
    if mode is None and (parsed.get('default_permissions') or parsed.get('permissions') or native_profiles):
        return {**named_root(config,root,before,text,parsed,profile.get('default_permissions',parsed.get('default_permissions',':workspace'))),'configuration_repair':repaired}
    result={'changed':False,'read_only':mode=='read-only','root':root.as_posix(),
            'restart_required':True,'custom_permissions':bool(parsed.get('permissions'))}
    if any(Path(p).expanduser().resolve()==root for p in roots):return result
    headers=list(re.finditer(r'(?m)^[ \t]*\[([^\[\]\r\n]+)\][ \t\r]*(?:#[^\r\n]*)?$',text))
    table=next((h for h in headers if h.group(1).strip()=='sandbox_workspace_write'),None)
    lo=table.end() if table else 0
    hi=next((h.start() for h in headers if h.start()>lo),len(text)) if table else (headers[0].start() if headers else len(text))
    key='writable_roots' if table else r'sandbox_workspace_write\s*\.\s*writable_roots'
    match=re.search(r'(?m)^[ \t]*'+key+r'[ \t]*=[ \t]*\[',text[lo:hi])
    encoded=json.dumps(root.as_posix(),ensure_ascii=False)
    if match:
        start=lo+match.end()-1;end=array_end(text,start)
        # Add before the closing bracket; retain existing comments and spelling.
        prefix='' if not roots else ','
        inner=text[start+1:end]
        significant=re.sub(r'#[^\n]*','',inner).rstrip()
        if significant.endswith(','):prefix=''
        addition=('\n' if inner and not inner.endswith('\n') else '')+prefix+encoded+'\n'
        updated=text[:end]+addition+text[end:]
    elif table:
        updated=text[:hi].rstrip()+'\nwritable_roots = ['+encoded+']\n\n'+text[hi:]
    else:
        if 'sandbox_workspace_write' in parsed:
            raise ValueError('Codex 使用内联沙盒配置，不能安全追加；原配置保留，请联系作者。')
        updated=text.rstrip()+'\n\n[sandbox_workspace_write]\nwritable_roots = ['+encoded+']\n'
    expected=json.loads(json.dumps(parsed));expected.setdefault('sandbox_workspace_write',{})['writable_roots']=[*roots,root.as_posix()]
    if tomllib.loads(updated)!=expected:raise ValueError('可写目录修改触及其他设置，已取消。')
    return {**result,'configuration':'legacy','changed':True,'backup':write_config(config,before,updated)}


def setup(core,python):
    check_dependencies(python)
    if core.HOST!='codex':return {'applicable':False}
    native_profiles=False
    try:
        cli=core.find_codex()
        help_text=subprocess.run([str(cli),'sandbox','--help'],capture_output=True,text=True,timeout=15,
                                 creationflags=0x08000000 if os.name=='nt' else 0).stdout
        native_profiles='--permission-profile' in help_text
    except (OSError,RuntimeError,subprocess.SubprocessError):pass
    root=core.app_home();result=register_root(core.codex_home()/'config.toml',root,native_profiles=native_profiles)
    folder=root/'runtime';folder.mkdir(parents=True,exist_ok=True)
    launcher=folder/'kb_launcher.py'
    raw=Path(__file__).read_bytes()
    if not launcher.exists() or launcher.read_bytes()!=raw:
        temporary=folder/('kb-'+uuid.uuid4().hex+'.tmp');temporary.write_bytes(raw);os.replace(temporary,launcher)
    cfg=core.codex_home()/'config.toml';before=cfg.read_bytes() if cfg.exists() else b'';text=before.decode('utf-8-sig')
    for kind,server in KINDS.items():
        text=core.remove_toml_section(text,'mcp_servers.'+server+'.env')
        text=core.remove_toml_section(text,'mcp_servers.'+server)
        text=text.rstrip()+'\n\n[mcp_servers.'+server+']\ncommand = '+json.dumps(str(python))+'\nargs = '+json.dumps(['-B',str(launcher),'--root',str(root),'--kb',kind])+'\nenabled = true\nrequired = false\nstartup_timeout_sec = 60\ntool_timeout_sec = 120\n'
    validate_config(text)
    if text.encode('utf-8')!=before:
        write_config(cfg,before,text)
    core.atomic_json(root/'runtime/sandbox-ready.json',{'schema':2,**result,'kb_launcher':str(launcher)})
    return result


def kb_command(root,kind):
    root=Path(root).resolve()
    if kind not in KINDS:raise ValueError('未知知识库。')
    state=json.loads((root/'current.json').read_text(encoding='utf-8'))
    source=Path(state['source']).resolve()
    expected=root/'marketplace/versions'/state['plugin_version']/'plugins/starsky-amazon-agent'
    if source!=expected.resolve():raise ValueError('知识库安装路径不匹配，请先启动星空完成解锁。')
    manifest=json.loads((source/'.codex-plugin/plugin.json').read_text(encoding='utf-8'))
    if manifest.get('name')!='starsky-amazon-agent' or manifest.get('version')!=state['plugin_version']:
        raise ValueError('知识库安装版本不匹配，请先启动星空完成解锁。')
    folder=source/'mcp'/kind
    if not (folder/'server.py').is_file() or not (folder/'kb').is_dir():raise ValueError('知识库资料尚未就绪，请先启动星空完成解锁。')
    return [state['python'],'-B',str(folder/'server.py'),'--kb',str(folder/'kb')]


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--kb',choices=KINDS,required=True)
    args=parser.parse_args()
    try:
        command=kb_command(args.root,args.kb)
        environment={**os.environ,'PYTHONUTF8':'1','PYTHONDONTWRITEBYTECODE':'1'}
        if os.name=='nt':
            # Windows CRT exec with a venv interpreter can crash while replacing
            # inherited JSON-RPC pipes. Preserve stdio with a child + exit status.
            raise SystemExit(subprocess.call(command,env=environment,stdin=sys.stdin,stdout=sys.stdout,
                                            stderr=sys.stderr,creationflags=0x08000000))
        os.execvpe(command[0],command,environment)
    except Exception as exc:
        print('星空知识库未启动：'+(str(exc) if isinstance(exc,ValueError) else '请先说「启动星空」完成安装解锁。'),file=sys.stderr)
        raise SystemExit(1)
