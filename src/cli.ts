import {dispatch} from './mcp/server.js';
const [name,input='{}']=process.argv.slice(2);
dispatch(name,JSON.parse(input)).then(r=>console.log(JSON.stringify(r,null,2))).catch(e=>{console.error(String(e));process.exitCode=1;});
