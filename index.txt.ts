import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-teacher-token, x-attempt-token",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status=200) => new Response(JSON.stringify(body), {status,headers:{...cors,"Content-Type":"application/json"}});
const secretSet = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS") || "{}");
const serviceKey = secretSet.default || Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
const url = Deno.env.get("SUPABASE_URL") || "";
const db = createClient(url, serviceKey, {auth:{persistSession:false}});
const teacherCode = Deno.env.get("TEACHER_CODE") || "";

async function hash(s:string){const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");}
function token(){const a=new Uint8Array(32);crypto.getRandomValues(a);return [...a].map(x=>x.toString(16).padStart(2,"0")).join("");}
function fail(message:string,status=400){throw Object.assign(new Error(message),{status});}
async function teacher(req:Request){
  const raw=req.headers.get("x-teacher-token")||"";if(!raw)fail("Нет сессии преподавателя.",401);
  const {data,error}=await db.from("teacher_sessions").select("*").eq("token_hash",await hash(raw)).gt("expires_at",new Date().toISOString()).maybeSingle();
  if(error||!data)fail("Сессия преподавателя истекла. Войдите снова.",401);
}
async function attempt(req:Request){
  const raw=req.headers.get("x-attempt-token")||"";if(!raw)fail("Не найдена попытка.",401);
  const {data,error}=await db.from("attempts").select("*,works(*)").eq("token_hash",await hash(raw)).maybeSingle();
  if(error||!data)fail("Попытка не найдена.",404);
  return data;
}
async function annul(a:any,reason:string){
  await db.from("attempts").update({status:"annulled",annul_reason:reason,finished_at:new Date().toISOString(),away_at:null}).eq("id",a.id);
}
async function enforce(a:any){
  if(a.status!=="active")fail(a.status==="annulled"?"Попытка аннулирована.":"Работа уже завершена.",409);
  const now=Date.now();
  if(new Date(a.ends_at).getTime()<=now){const g=await grade(a);await db.from("attempts").update({status:"completed",score:g.score,max_score:g.max,manual_pending:g.pending,finished_at:new Date().toISOString(),away_at:null}).eq("id",a.id);fail("Время работы закончилось.",409);}
  const awaySince=a.away_at?new Date(a.away_at).getTime():new Date(a.last_seen_at).getTime();
  if(now-awaySince>5000){await annul(a,"Отсутствие активности более 5 секунд");fail("Попытка аннулирована: отсутствие активности более 5 секунд.",409);}
}
async function updatePresence(a:any){await db.from("attempts").update({last_seen_at:new Date().toISOString(),away_at:null}).eq("id",a.id);}
function parseNumericAnswer(input:string):number|null{
  // Safe arithmetic parser: no eval/Function, identifiers, or executable syntax.
  const source=String(input??"").trim().replace(/,/g,".").replace(/\s+/g,"");
  if(!source||source.length>120)return null;
  const tokens=source.match(/(?:\d+(?:\.\d*)?|\.\d+|[()+\-*/^])/g)||[];
  if(tokens.join("")!==source)return null;
  let i=0;
  const primary=():number=>{const t=tokens[i++];if(t==="+")return primary();if(t==="-")return -primary();if(t==="("){const v=add();if(tokens[i++]!==")")throw new Error("paren");return v;}if(t===undefined)throw new Error("value");const n=Number(t);if(!Number.isFinite(n))throw new Error("number");return n;};
  const power=():number=>{const v=primary();if(tokens[i]==="^"){i++;return Math.pow(v,power());}return v;};
  const mul=():number=>{let v=power();while(tokens[i]==="*"||tokens[i]==="/"){const op=tokens[i++],r=power();v=op==="*"?v*r:v/r;}return v;};
  const add=():number=>{let v=mul();while(tokens[i]==="+"||tokens[i]==="-"){const op=tokens[i++],r=mul();v=op==="+"?v+r:v-r;}return v;};
  try{const value=add();return i===tokens.length&&Number.isFinite(value)?value:null;}catch{return null;}
}
async function grade(a:any){
  const {data:tasks}=await db.from("tasks").select("*").eq("work_id",a.work_id).order("position");
  let score=0,max=0,pending=false;
  for(const t of tasks||[]){
    max+=t.points;
    const answer=String(a.answers?.[t.id]??"").trim();
    if(t.answer_type==="choice" && answer===String(t.correct_answer).trim())score+=t.points;
    if(t.answer_type==="numeric"){
      const actual=parseNumericAnswer(answer);
      const expected=parseNumericAnswer(String(t.correct_answer??""));
      if(actual!==null&&expected!==null&&Math.abs(actual-expected)<=Number(t.tolerance||0))score+=t.points;
    }
    if(t.answer_type==="manual")pending=true;
  }
  return {score,max,pending};
}
Deno.serve(async(req)=>{
  if(req.method==="OPTIONS")return new Response("ok",{headers:cors});
  try{
    if(req.method!=="POST")fail("Используй POST.",405);
    const body=await req.json();const action=body.action;
    if(!serviceKey||!url)fail("Сервер не настроен.",500);
    if(action==="teacher_login"){
      if(!/^\d{4}$/.test(body.code||""))fail("PIN должен состоять ровно из четырёх цифр.");
      const ip=req.headers.get("x-forwarded-for")?.split(",")[0]||"unknown";
      const key=await hash("teacher-login:"+ip);
      const {data:lim}=await db.from("login_limits").select("*").eq("key",key).maybeSingle();
      const now=Date.now();
      if(lim&&now-new Date(lim.window_started_at).getTime()<600000&&lim.attempts>=8)fail("Слишком много попыток. Подожди 10 минут.",429);
      await db.from("login_limits").upsert({key,attempts:lim&&now-new Date(lim.window_started_at).getTime()<600000?lim.attempts+1:1,window_started_at:lim&&now-new Date(lim.window_started_at).getTime()<600000?lim.window_started_at:new Date().toISOString()});
      if(!teacherCode||body.code!==teacherCode)fail("Неверный код преподавателя.",401);
      await db.from("login_limits").delete().eq("key",key);
      const raw=token();await db.from("teacher_sessions").insert({token_hash:await hash(raw),expires_at:new Date(Date.now()+12*60*60*1000).toISOString()});
      return json({ok:true,data:{token:raw}});
    }
    if(action==="student_list"){
      const {data,error}=await db.from("works").select("id,title,section,topic,difficulty,duration_minutes").eq("published",true).order("created_at",{ascending:false});
      if(error)throw error;return json({ok:true,data:{works:data||[]}});
    }
    if(action==="student_start"){
      const name=String(body.student_name||"").trim();
      if(name.length<3||name.length>90)fail("Введи имя и фамилию.");
      const {data:w}=await db.from("works").select("*").eq("id",body.work_id).eq("published",true).maybeSingle();
      if(!w)fail("Работа не найдена или ещё не опубликована.",404);
      const {data:tasks}=await db.from("tasks").select("id,position,prompt,answer_type,options,points").eq("work_id",w.id).order("position");
      if(!tasks?.length)fail("В работе пока нет заданий.");
      const raw=token(),started=new Date(),ends=new Date(started.getTime()+w.duration_minutes*60000);
      const {data:a,error}=await db.from("attempts").insert({work_id:w.id,student_name:name,token_hash:await hash(raw),ends_at:ends.toISOString(),max_score:tasks.reduce((s,t)=>s+t.points,0)}).select("*").single();
      if(error)throw error;
      return json({ok:true,data:{token:raw,attempt:{id:a.id,started_at:a.started_at,ends_at:a.ends_at},work:w,tasks}});
    }
    if(action==="student_ping"||action==="student_answer"||action==="student_leave"||action==="student_finish"){
      const a=await attempt(req);
      if(action==="student_ping"){
        await enforce(a);await updatePresence(a);return json({ok:true,data:{status:"active"}});
      }
      if(action==="student_leave"){
        if(a.status==="active")await db.from("attempts").update({away_at:new Date().toISOString()}).eq("id",a.id);
        return json({ok:true,data:{status:a.status}});
      }
      if(action==="student_finish" && a.status==="completed")return json({ok:true,data:{status:"completed",score:a.score,max_score:a.max_score,manual_pending:a.manual_pending}});
      if(action==="student_finish" && a.status==="annulled")return json({ok:true,data:{status:"annulled",score:a.score,max_score:a.max_score,manual_pending:false}});
      if(action==="student_finish" && a.status==="active" && Date.now()>=new Date(a.ends_at).getTime()){
        const g=await grade(a);
        const {error}=await db.from("attempts").update({status:"completed",score:g.score,max_score:g.max,manual_pending:g.pending,finished_at:new Date().toISOString(),away_at:null}).eq("id",a.id);
        if(error)throw error;
        return json({ok:true,data:{status:"completed",score:g.score,max_score:g.max,manual_pending:g.pending}});
      }
      await enforce(a);
      if(action==="student_answer"){
        const {data:t}=await db.from("tasks").select("id").eq("id",body.task_id).eq("work_id",a.work_id).maybeSingle();
        if(!t)fail("Задание не найдено.");
        const {error}=await db.rpc("matklass_save_attempt_answer",{p_attempt_id:a.id,p_task_id:body.task_id,p_answer:String(body.answer??"").slice(0,2000)});
        if(error)throw error;return json({ok:true,data:{saved:true}});
      }
      if(action==="student_finish"){
        const g=await grade(a);
        const {error}=await db.from("attempts").update({status:"completed",score:g.score,max_score:g.max,manual_pending:g.pending,finished_at:new Date().toISOString(),away_at:null}).eq("id",a.id);
        if(error)throw error;return json({ok:true,data:{status:"completed",score:g.score,max_score:g.max,manual_pending:g.pending}});
      }
    }
    if(action?.startsWith("teacher_")){
      await teacher(req);
      if(action==="teacher_create_work"){
        const w=body.work||{},tasks=body.tasks||[];
        if(!w.title||!w.topic||!tasks.length||tasks.length>80)fail("Проверь название, тему и задания.");
        const scale=w.grade_scale&&typeof w.grade_scale==="object"?w.grade_scale:{};
        const gradeScale:any={};
        for(const k of ["3","4","5"]){if(scale[k]!==undefined&&scale[k]!==null&&scale[k]!==""){const v=Number(scale[k]);if(!Number.isFinite(v)||v<0||v>100)fail("Порог оценки должен быть от 0 до 100 процентов.");gradeScale[k]=v;}}
        if(Object.keys(gradeScale).length && !(Number(gradeScale[5])>=Number(gradeScale[4]) && Number(gradeScale[4])>=Number(gradeScale[3])))fail("Пороги должны идти по убыванию: 5, затем 4, затем 3.");
        const {data:created,error}=await db.from("works").insert({title:String(w.title).slice(0,100),section:w.section,topic:String(w.topic).slice(0,100),difficulty:w.difficulty,duration_minutes:Math.max(1,Math.min(240,Number(w.duration_minutes)||30)),mode:w.mode==="free"?"free":"test",grade_scale:gradeScale,published:!!w.published}).select("*").single();
        if(error)throw error;
        const rows=tasks.map((t:any,i:number)=>({work_id:created.id,position:i+1,prompt:String(t.prompt).slice(0,3000),answer_type:["choice","numeric","manual"].includes(t.answer_type)?t.answer_type:"manual",options:Array.isArray(t.options)?t.options.slice(0,10):[],correct_answer:String(t.correct_answer).slice(0,2000),tolerance:Math.max(0,Number(t.tolerance)||0),points:Math.max(1,Math.min(100,Number(t.points)||1)),template_source:t.template_source||null}));
        const {error:te}=await db.from("tasks").insert(rows);if(te){await db.from("works").delete().eq("id",created.id);throw te;}
        return json({ok:true,data:{work:created}});
      }
      if(action==="teacher_save_template"){
        const t=body.template||{};
        if(!t.title||!/[{](?:a|b|c|n)[}]/.test(String(t.prompt_pattern||""))||!t.answer_formula||Number(t.min_n)>Number(t.max_n))fail("Заполни шаблон: переменную {a}, {b}, {c} или {n}, формулу и диапазон.");
        const ranges=[t.min_n,t.max_n,t.min_b??1,t.max_b??10,t.min_c??1,t.max_c??10].map(Number);
        if(ranges.some(x=>!Number.isFinite(x))||ranges[0]>ranges[1]||ranges[2]>ranges[3]||ranges[4]>ranges[5])fail("Проверь диапазоны переменных.");
        const {data,error}=await db.from("task_templates").insert({title:String(t.title).slice(0,100),section:String(t.section||"Алгебра"),topic:String(t.topic||"Шаблон"),prompt_pattern:String(t.prompt_pattern).slice(0,1000),answer_formula:String(t.answer_formula).slice(0,200),min_n:ranges[0],max_n:ranges[1],min_b:ranges[2],max_b:ranges[3],min_c:ranges[4],max_c:ranges[5],points:Math.max(1,Math.min(100,Number(t.points)||1))}).select("*").single();
        if(error)throw error;return json({ok:true,data:{template:data}});
      }
      if(action==="teacher_templates"){
        const {data,error}=await db.from("task_templates").select("*").order("created_at",{ascending:false});
        if(error)throw error;return json({ok:true,data:{templates:data||[]}});
      }
      if(action==="teacher_delete_template"){
        const {error}=await db.from("task_templates").delete().eq("id",body.template_id);if(error)throw error;
        return json({ok:true,data:{deleted:true}});
      }
      if(action==="teacher_review_list"){
        const {data,error}=await db.from("attempts").select("id,student_name,work_id,answers,manual_scores,score,max_score,manual_pending,works(title)").eq("status","completed").eq("manual_pending",true).order("finished_at",{ascending:true}).limit(100);
        if(error)throw error;
        const result=[];
        for(const a of data||[]){
          const {data:tasks}=await db.from("tasks").select("id,prompt,correct_answer,points,answer_type").eq("work_id",a.work_id).eq("answer_type","manual").order("position");
          result.push({id:a.id,student_name:a.student_name,work_title:a.works?.title||"Работа",score:a.score||0,max_score:a.max_score||0,answers:a.answers||{},manual_scores:a.manual_scores||{},tasks:tasks||[]});
        }
        return json({ok:true,data:{attempts:result}});
      }
      if(action==="teacher_grade_manual"){
        const {data:a,error:ae}=await db.from("attempts").select("*").eq("id",body.attempt_id).eq("status","completed").maybeSingle();
        if(ae||!a)fail("Попытка не найдена.",404);
        const {data:tasks}=await db.from("tasks").select("id,points,answer_type").eq("work_id",a.work_id).eq("answer_type","manual");
        const scores=body.scores||{};let manualTotal=0;
        for(const t of tasks||[]){
          const val=Number(scores[t.id]??0);
          if(!Number.isFinite(val)||val<0||val>t.points)fail("Баллы за задание должны быть от 0 до максимума.");
          manualTotal+=val;
        }
        const auto=await grade(a);
        const autoScore=auto.score;
        const {error}=await db.from("attempts").update({manual_scores:scores,score:autoScore+manualTotal,manual_pending:false,teacher_comment:String(body.comment||"").slice(0,1000)}).eq("id",a.id);
        if(error)throw error;return json({ok:true,data:{score:autoScore+manualTotal}});
      }
      if(action==="teacher_works"){
        const {data,error}=await db.from("works").select("*").order("created_at",{ascending:false});if(error)throw error;
        return json({ok:true,data:{works:data||[]}});
      }
      if(action==="teacher_publish"){
        const {error}=await db.from("works").update({published:!!body.published}).eq("id",body.work_id);if(error)throw error;
        return json({ok:true,data:{updated:true}});
      }
      if(action==="teacher_delete_work"){
        const {error}=await db.from("works").delete().eq("id",body.work_id);if(error)throw error;
        return json({ok:true,data:{deleted:true}});
      }
      if(action==="teacher_results"){
        const workId=String(body.work_id||"");if(!workId)fail("Выбери работу.");
        const {data:work,error:we}=await db.from("works").select("id,title,grade_scale").eq("id",workId).maybeSingle();
        if(we||!work)fail("Работа не найдена.",404);
        const {data,error}=await db.from("attempts").select("id,student_name,status,started_at,finished_at,score,max_score,manual_pending,annul_reason,teacher_comment").eq("work_id",workId).order("started_at",{ascending:true}).limit(500);
        if(error)throw error;
        const scale=work.grade_scale||{};
        const rows=(data||[]).map((a:any)=>{let mark=null;if(a.status==="completed"&&!a.manual_pending&&Object.keys(scale).length&&Number(a.max_score)>0){const pct=Number(a.score||0)/Number(a.max_score)*100;mark=pct>=Number(scale[5]??101)?5:pct>=Number(scale[4]??101)?4:pct>=Number(scale[3]??101)?3:2;}return {...a,mark,percent:a.status==="completed"&&Number(a.max_score)>0?Math.round(Number(a.score||0)/Number(a.max_score)*1000)/10:null};});
        return json({ok:true,data:{work,attempts:rows}});
      }
      if(action==="teacher_dashboard"){
        const {data,error}=await db.from("attempts").select("id,work_id,student_name,status,started_at,last_seen_at,away_at,score,max_score,manual_pending,works(title)").order("started_at",{ascending:false}).limit(300);
        if(error)throw error;
        const now=Date.now(),rows=[];
        for(const a of data||[]){
          let status=a.status,away=false;
          const marker=a.away_at||a.last_seen_at;
          if(status==="active"&&now-new Date(marker).getTime()>5000){
            await db.from("attempts").update({status:"annulled",annul_reason:"Отсутствие активности более 5 секунд",finished_at:new Date().toISOString()}).eq("id",a.id);
            status="annulled";
          } else if(status==="active"&&a.away_at){away=true;}
          rows.push({student_name:a.student_name,work_title:a.works?.title||"Работа удалена",started_at:a.started_at,status,away,score:a.score,max_score:a.max_score,manual_pending:a.manual_pending});
        }
        return json({ok:true,data:{attempts:rows,counts:{active:rows.filter(x=>x.status==="active"&&!x.away).length,completed:rows.filter(x=>x.status==="completed").length,annulled:rows.filter(x=>x.status==="annulled").length,manual:rows.filter(x=>x.manual_pending).length}}});
      }
    }
    fail("Неизвестное действие.",404);
  }catch(e){
    console.error(e);
    return json({ok:false,error:e?.message||"Внутренняя ошибка сервера"},e?.status||500);
  }
});