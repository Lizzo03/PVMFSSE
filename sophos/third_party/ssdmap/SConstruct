import os

env = Environment()

try:
    env.Append(ENV = {'TERM' : os.environ['TERM']}) # Keep our nice terminal environment (like colors ...)
except:
    print "Not running in a terminal"


if FindFile('config.scons', '.'):
    SConscript('config.scons', exports='env')
    
env.Append(CCFLAGS=['-Wall', '-march=native', '-maes', '-fPIC'])
env.Append(CXXFLAGS=['-std=c++11'])

env['STATIC_AND_SHARED_OBJECTS_ARE_THE_SAME']=1

debug = ARGUMENTS.get('debug', 0)

if int(debug):
    env.Append(CCFLAGS = ['-g','-O'])
else:
	env.Append(CCFLAGS = ['-O2'])



def run_test(target, source, env):
    app = str(source[0].abspath)
    if os.spawnl(os.P_WAIT, app, app)==0:
        return 0
    else:
        return 1

bld = Builder(action = run_test)
env.Append(BUILDERS = {'Test' :  bld})

objects = SConscript('src/build.scons', exports='env', variant_dir='build', duplicate=0)

Clean(objects, 'build')

# debug = env.Program('check',['checks.cpp'] + objects, CPPPATH = ['src'])
debug = env.Program('debug',['main.cpp'] + objects, CPPPATH = ['src'])

# env.Alias('check', debug)

Default(debug)


shared_lib_env = env.Clone();

if env['PLATFORM'] == 'darwin':
    # We have to add '@rpath' to the library install name
    shared_lib_env.Append(LINKFLAGS = ['-install_name', '@rpath/libssdmap.dylib'])

library_build_prefix = 'library'
shared_lib = shared_lib_env.SharedLibrary(library_build_prefix+'/lib/libssdmap',objects);
static_lib = env.StaticLibrary(library_build_prefix+'/lib/libssdmap',objects)

headers = Glob('src/*.h') + Glob('src/*.hpp')
headers_lib = [env.Install(library_build_prefix+'/include/ssdmap', headers)]

env.Clean(headers_lib,[library_build_prefix+'/include'])

Alias('headers', headers_lib)
Alias('lib', [shared_lib, static_lib] + headers_lib)
# Alias('lib', [lib_install] + headers_lib)
Clean('lib', 'library')


doc = env.Command('html', [], 'doxygen')
env.AlwaysBuild(doc)
env.Alias('doc', [doc])

test_env = env.Clone()
    
test_prog = test_env.Program('check', ['checks.cpp'] + objects, CPPPATH = ['src'])
test_run = test_env.Test('test_run', test_prog)
Depends(test_run, test_prog)

test_env.Alias('check', [test_prog, test_run])

test_env.Clean('check', ['check'] + objects)




