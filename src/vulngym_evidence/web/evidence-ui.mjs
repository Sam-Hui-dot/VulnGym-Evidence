// Pure display helpers. Only literal, program-verified source ranges are highlighted.
export function sourceLines(evidence) {
  return String(evidence?.numbered_source || "").split("\n").flatMap(line => {
    const match = line.match(/^\s*(\d+)\s*\| ?(.*)$/);
    return match ? [{number: Number(match[1]), text: match[2]}] : [];
  });
}

export function sourceSelection(row, evidence) {
  const bound = evidence.filter(e => row.evidence_refs.includes(e.evidence_id));
  const observations = [...(row.countercheck?.observations || []),
    ...(row.critic_countercheck?.observations || [])].filter(o => o.quote_verified);
  const chosen = observations.map(o => bound.find(e => e.evidence_id === o.evidence_id))
    .find(e => sourceLines(e).length) || bound.find(e => sourceLines(e).length);
  if (!chosen) return {evidence: null, lines: [], highlighted: [], focus: 0};
  const lines = sourceLines(chosen), highlighted = new Set();
  for (const o of observations.filter(o => o.evidence_id === chosen.evidence_id)) {
    const range = o.source_line_range;
    if (!Array.isArray(range) || range.length !== 2) continue;
    const literal = lines.filter(l => l.number >= range[0] && l.number <= range[1]);
    if (literal.length && literal.map(l => l.text).join("\n") === o.quote) {
      literal.forEach(l => highlighted.add(l.number));
    }
  }
  if (!highlighted.size) {
    const range = String(chosen.declared_line || "").split("-").map(Number);
    const last = range[1] || range[0];
    lines.filter(l => l.number >= range[0] && l.number <= last)
      .forEach(l => highlighted.add(l.number));
  }
  const focus = lines.findIndex(l => highlighted.has(l.number));
  return {evidence: chosen, lines, highlighted: [...highlighted], focus: Math.max(0, focus)};
}

export function sourceWindowStart(selection, capacity) {
  const focus = Math.max(0, selection.focus || 0);
  const highlighted = selection.lines.flatMap((line, index) =>
    selection.highlighted.includes(line.number) ? [index] : []);
  const last = highlighted.at(-1) ?? focus;
  const start = Math.min(focus, Math.max(0, focus - 2, last - capacity + 1));
  return Math.min(start, Math.max(0, selection.lines.length - capacity));
}
export function reviewAdvice(row) {
  if (row.review_status && row.review_status !== "completed") {
    return {title: "下一步", text: "本条未形成有效判断。检查运行记录中的材料或模型错误，再重新复核。"};
  }
  if (row.verdict === "uncertain") {
    return {title: "待补证据", text: row.reason};
  }
  return row.verdict === "contradicted"
    ? {title: "修订建议", text: "回到报告原句，结合下方源码修订这条说法，保留文件、版本与引用位置。"}
    : {title: "复核范围", text: row.kind === "source_location"
      ? "此项确认引用位置一致；报告对代码的解释需要分别核查。"
      : "当前证据支持这条具体说法，可保留依据供人工复查。"};
}

export function reviewText(row, request) {
  const advice = reviewAdvice(row);
  return ["待核查说法：" + row.text, "复核理由：" + row.reason,
    advice.title + "：" + advice.text, "仓库：" + request.repo_url,
    "版本：" + request.reviewed_commit].join("\n\n");
}
