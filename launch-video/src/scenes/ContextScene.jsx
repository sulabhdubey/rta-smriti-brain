import { Img, interpolate, staticFile, useCurrentFrame } from "remotion";
import { Brand, Eyebrow, Reveal, Scene, palette } from "../ui";

export const ContextScene = () => {
  const frame = useCurrentFrame();
  const steps = ["Select the canonical brain", "Review capture and truth", "Set objective and authority", "Compile a governed pack"];
  return <Scene><Brand />
    <div style={{ position: "absolute", left: 105, top: 205, width: 760, zIndex: 2 }}><Reveal><Eyebrow>v1.0.2 · Governed context</Eyebrow></Reveal><Reveal from={14}><h1 style={{ margin: "18px 0 30px", fontSize: 82, lineHeight: 1 }}>Only governed context.<br />For this task.</h1></Reveal>
      <div style={{ display: "grid", gap: 14 }}>{steps.map((step,index)=><div key={step} style={{ display:"grid", gridTemplateColumns:"54px 1fr", alignItems:"center", padding:"15px 0", color:index===3?palette.text:palette.muted, fontSize:27, opacity:interpolate(frame,[40+index*18,58+index*18],[0,1],{extrapolateLeft:"clamp",extrapolateRight:"clamp"}) }}><span style={{display:"grid",placeItems:"center",width:38,height:38,border:`1px solid ${index===3?palette.teal:palette.line}`,borderRadius:"50%",color:index===3?palette.teal:palette.muted,fontSize:17}}>{index+1}</span>{step}</div>)}</div>
    </div>
    <Img src={staticFile("file-explorer-v1.0.2.png")} style={{ position:"absolute",right:-120,bottom:-20,width:1230,border:`1px solid ${palette.line}`,borderRadius:10,boxShadow:"0 40px 100px #000",opacity:interpolate(frame,[0,25],[0,1],{extrapolateRight:"clamp"}),translate:`${interpolate(frame,[0,45],[80,0],{extrapolateRight:"clamp"})}px 0` }} />
  </Scene>;
};
