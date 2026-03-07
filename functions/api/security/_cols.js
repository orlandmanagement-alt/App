export async function tableCols(env, table){
  const r = await env.DB.prepare(`PRAGMA table_info('${table}')`).all();
  return new Set((r.results||[]).map(x=>String(x.name)));
}

export function has(colset, col){ return colset.has(String(col)); }
