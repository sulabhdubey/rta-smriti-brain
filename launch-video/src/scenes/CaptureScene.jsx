import { Img, Easing, interpolate, staticFile, useCurrentFrame } from "remotion";
import { Brand, Eyebrow, Reveal, Scene, palette } from "../ui";

const controls = [
  ["Bounded spool", "Backpressure fails closed"],
  ["Redaction first", "Secrets filtered before durable queueing"],
  ["Read-only replay", "Captured actions never execute"],
  ["Explicit promotion", "Agent text starts unverified"],
];

export const CaptureScene = () => {
  const frame = useCurrentFrame();
  return <Scene><Brand />
    <div style={{ position: "absolute", left: 100, top: 190, zIndex: 2, width: 720 }}>
      <Reveal><Eyebrow>v1.0.2 · Universal Capture</Eyebrow></Reveal>
      <Reveal from={14}><h1 style={{ margin: "18px 0 20px", fontSize: 86, lineHeight: 1 }}>An agent flight<br />recorder. Local.</h1></Reveal>
      <Reveal from={30}><p style={{ margin: 0, color: palette.muted, fontSize: 30, lineHeight: 1.45 }}>Capture activity without confusing a transcript with project truth.</p></Reveal>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 34 }}>
        {controls.map(([title, copy], index) => <div key={title} style={{ padding: "15px 17px", borderLeft: `2px solid ${index === 3 ? palette.amber : palette.teal}`, background: "rgba(8,19,29,.9)", opacity: interpolate(frame,[45+index*10,62+index*10],[0,1],{extrapolateLeft:"clamp",extrapolateRight:"clamp"}) }}><strong style={{ display:"block",fontSize:20 }}>{title}</strong><span style={{ color:palette.muted,fontSize:15 }}>{copy}</span></div>)}
      </div>
    </div>
    <Img src={staticFile("capture-v1.0.2.png")} style={{ position: "absolute", right: -120, bottom: -10, width: 1250, border: `1px solid ${palette.line}`, borderRadius: 10, boxShadow: "0 40px 100px #000", rotate: "-1deg", scale: interpolate(frame, [0, 45], [.93, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: Easing.bezier(.16,1,.3,1) }), opacity: interpolate(frame, [0, 22], [0, 1], { extrapolateRight: "clamp" }) }} />
  </Scene>;
};