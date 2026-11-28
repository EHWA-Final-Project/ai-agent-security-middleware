import { useState } from 'react'

const brandingRoot = `${import.meta.env.BASE_URL}branding/`

export function BrandMark() {
  return <img className="brand-mark" src={`${brandingRoot}guardon-mark.svg`} width="34" height="34" alt="" />
}

/** The supplied university asset is kept intact; missing assets fall back to text. */
export function ProjectCredit() {
  const [logoUnavailable, setLogoUnavailable] = useState(false)
  return <footer className="project-credit" aria-label="프로젝트 제작 정보">
    <div className="project-university">
      {!logoUnavailable && <img src={`${brandingRoot}ewha-symbol.png`} width="26" height="30" alt="" onError={() => setLogoUnavailable(true)} />}
      <span>이화여자대학교</span>
    </div>
    <span className="project-team">GuardOn Team</span>
    <p className="project-members"><span>오지송 · 이지원</span><span>Fatin · Wana</span></p>
  </footer>
}
