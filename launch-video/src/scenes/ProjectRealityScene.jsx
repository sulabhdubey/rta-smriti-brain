import { Img, Easing, interpolate, staticFile, useCurrentFrame } from "remotion";
import { Brand, Eyebrow, Reveal, Scene, palette } from "../ui";

const facts = [
  ["Readiness", "Freshness, conflicts, decision debt"],
  ["Project twin", "Expected state versus observed evidence"],
  ["Change impact", "Bounded hints, never execution authority"],
];

export const ProjectRealityScene = () => {
  const frame = useCurrentFrame();
  return <Scene><Brand />
    <div style={{ position: "absolute", left: 100, top: 190, zIndex: 2, width: 720 }}>
      <Reveal><Eyebrow>v1 · Project Reality</Eyebrow></Reveal>
      <Reveal from={14}><h1 style={{ margin: "18px 0 20px", fontSize: 82, lineHeight: 1 }}>Know what is ready.<br />And what is not.</h1></Reveal>
      <Reveal from={30}><p style={{ margin: 0, color: palette.muted, fontSize: 29, lineHeight: 1.45 }}>One deterministic projection reconciles repository evidence, truth, work state, decisions, and governed media.</p></Reveal>
      <div style={{ display: "grid", gap: 12, marginTop: 30 }}>
        {facts.map(([title, copy], index) => <div key={title} style={{ display: "grid", gridTemplateColumns: "170px 1fr", padding: "14px 16px", borderLeft: "2px solid " + (index === 1 ? palette.amber : palette.teal), background: "rgba(8,19,29,.9)", opacity: interpolate(frame, [48 + index * 11, 66 + index * 11], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }) }}><strong style={{ fontSize: 20 }}>{title}</strong><span style={{ color: palette.muted, fontSize: 17 }}>{copy}</span></div>)}
      </div>
    </div>
    <Img src={staticFile("project-reality-v1.0.2.png")} style={{ position: "absolute", right: -110, bottom: -16, width: 1240, border: "1px solid " + palette.line, borderRadius: 10, boxShadow: "0 40px 100px #000", rotate: "-1deg", scale: interpolate(frame, [0, 45], [.93, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: Easing.bezier(.16, 1, .3, 1) }), opacity: interpolate(frame, [0, 22], [0, 1], { extrapolateRight: "clamp" }) }} />
  </Scene>;
};
