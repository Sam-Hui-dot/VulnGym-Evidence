import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {sourceLines,sourceSelection,sourceWindowStart,reviewAdvice,reviewText}
  from '../src/vulngym_evidence/web/evidence-ui.mjs';

const sample=JSON.parse(readFileSync(new URL('../src/vulngym_evidence/web/demo-result.json',import.meta.url),'utf8'));
test('real counterevidence exposes encoding before substitution',()=>{
  const selected=sourceSelection(sample.results[0],sample.evidence_packet.evidence);
  assert.deepEqual(selected.highlighted,[214,215]);
  assert.match(selected.lines[selected.focus].text,/quote\(str\(param_value\)/);
});
test('a false literal quote cannot highlight an unverified line',()=>{
  const row=structuredClone(sample.results[0]);
  row.countercheck.observations=[{quote_verified:true,evidence_id:row.evidence_refs[0],
    source_line_range:[214,214],quote:'fabricated'}];
  delete row.critic_countercheck;
  assert.deepEqual(sourceSelection(row,sample.evidence_packet.evidence).highlighted,[215]);
});
test('unbound source is never displayed as evidence for this claim',()=>{
  const row=structuredClone(sample.results[0]); row.evidence_refs=[];
  assert.equal(sourceSelection(row,sample.evidence_packet.evidence).evidence,null);
});
test('number parsing preserves code indentation',()=>{
  assert.deepEqual(sourceLines({numbered_source:' 12 |     x = 1\ninvalid'}),[{number:12,text:'    x = 1'}]);
});
test('uncertainty lists the actual missing evidence and errors remain failures',()=>{
  const row=sample.results[1];
  assert.deepEqual(reviewAdvice(row),{title:'待补证据',text:row.reason});
  assert.match(reviewAdvice({...row,review_status:'failed'}).text,/未形成有效判断/);
});
test('copyable review retains reason and exact version',()=>{
  const value=reviewText(sample.results[0],sample.request);
  assert.ok(value.includes(sample.results[0].reason));
  assert.ok(value.includes(sample.request.reviewed_commit));
});

test('a three-line viewport keeps both verified encoding and substitution lines',()=>{
  const selected=sourceSelection(sample.results[0],sample.evidence_packet.evidence);
  const start=sourceWindowStart(selected,3);
  const visible=selected.lines.slice(start,start+3).map(line=>line.number);
  assert.ok(visible.includes(214));
  assert.ok(visible.includes(215));
  assert.ok(start>=0 && start+3<=selected.lines.length);
});