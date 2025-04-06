const process = {env:{url: location.href}}
const url = process.env.url;
const x = (new DOMParser).parseFromString(await ((await fetch(url)).text()), "text/html");
var secondaryLogo = x.querySelector("header .brand-logo__theme-link")
  secondaryLogo = secondaryLogo.href //link of sub brand, which by the ending path, one could infer the subbrand, like CNN *Business*, CNN *Politics*, 
var breadcrumb = x.querySelector(".breadcrumb")?.querySelectorAll("a") || [];
  breadcrumb = [...breadcrumb].map(a=>["a", a.innerText, a.href]);
// like Business / Economy or Politics / Culture
const headline = x.querySelector(".headline__text").innerText.trim()
var byline = [...x.querySelector(".byline__names").querySelectorAll("a")].map(a=>["a", a.innerText, a.href]);
const lastByline = x.querySelector(".byline__names").lastChild; //will be first element on byline to display the news source like CNN or AP or etc like bodysource
if(lastByline instanceof Text) byline.unshift(['t', lastByline.textContent.slice(2).trim()]);
if(lastByline instanceof HTMLAnchorElement){byline.pop(); byline.unshift(['a', lastByline.textContent, byline[0].href])}
const readTime = x.querySelector(".headline__sub-description").innerText.trim(); //time it takes to read
const timeStamp = x.querySelector(".timestamp").innerText.trim(); //when updated or posted
const body = x.querySelector("main")
const bodyContent = x.querySelector(".article__content");
var bodySourceLocation = null; //display location of news source
var bodySource = null; //like lastbyline, display news source
var newBody = []
for(const elem of bodyContent.children){
  /*e*/ if(elem.classList.contains("paragraph")){//p
    newBody.push(["p", 
      ...([...elem.childNodes].map((subelem, subelemInd)=>{//not children
        if(subelem instanceof Text){
          return ["t", 
            (subelemInd===0)?
              (subelem.textContent.trimStart())
              :(
                (subelemInd +1 == elem.childNodes.length)?
                  (subelem.textContent.trimEnd())
                  :(subElem.textContent)
              )
          ];
        }
        if(subelem instanceof HTMLAnchorElement){
          return ["a", subelem.innerText, subelem.href];
        }
      }))
    ]);
  }else if(elem.classList.contains("subheader")){//h2
    newBody.push(["h", elem.innerText.trim()])
  }else if(elem.classList.contains("source")){
    bodySourceLocation = elem.querySelector(".source__location").innerText;
    bodySource = elem.querySelector(".source__text").innerText;
  }else if(elem.classList.contains("image")){
    newBody.push(["i", 
      elem.querySelector(".image__caption").innerText.trim(), //caption
      elem.querySelector(".image__credit").innerText.trim(), //credit
      elem.querySelector("picture").querySelector("img").src, //img
      ...([...elem.querySelector("picture").querySelectorAll("source")].map(src=>[src.srcset, src.media])) //source(s)
    ])
  }else if(elem.classList.contains("map")){
    newBody.push(["m", elem.getAttribute("data-latitude"), elem.getAttribute("data-longitude"), elem.getAttribute("data-zoom")]);
  }else if(elem.classList.contains("related-content")){
    newBody.push(["r",
      elem.querySelector(".related-content__headline-text").innerText,
      elem.querySelector("a").href,
      elem.querySelector("img")?.src
    ]);
  }else {
    throw ["wtf", elem];
  }
}
const obj = {headline, readTime, timeStamp, newBody, secondaryLogo, breadcrumb, byline}


function convertToHTMLDocument(obj) {
    const doc = document.implementation.createHTMLDocument(obj.headline);
    const body = doc.body;
  
    // Helper to create element with optional text and attributes
    function createEl(tag, text = '', attrs = {}) {
      const el = doc.createElement(tag);
      if (text) el.textContent = text;
      for (const [key, val] of Object.entries(attrs)) {
        el.setAttribute(key, val);
      }
      return el;
    }
  
    // Add Headline
    const headlineEl = createEl('h1', obj.headline);
    body.appendChild(headlineEl);
  
    // Add Read Time and Timestamp
    const meta = createEl('div');
    meta.appendChild(createEl('span', obj.readTime));
    meta.appendChild(doc.createTextNode(' • '));
    meta.appendChild(createEl('span', obj.timeStamp));
    body.appendChild(meta);
  
    // Add Breadcrumbs
    if (obj.breadcrumb.length > 0) {
      const nav = createEl('nav');
      obj.breadcrumb.forEach((b, idx) => {
        const [type, text, href] = b;
        if (type === 'a') {
          nav.appendChild(createEl('a', text, { href }));
          if (idx < obj.breadcrumb.length - 1) {
            nav.appendChild(doc.createTextNode(' / '));
          }
        }
      });
      body.appendChild(nav);
    }
  
    // Add Byline
    const byline = createEl('div');
    obj.byline.forEach(([type, text, href]) => {
      if (type === 't') {
        byline.appendChild(createEl('span', text));
      } else if (type === 'a') {
        byline.appendChild(createEl('a', text, { href }));
      }
      byline.appendChild(doc.createTextNode(' '));
    });
    body.appendChild(byline);
  
    // Add Secondary Logo
    const logo = createEl('a', 'Subbrand', { href: obj.secondaryLogo });
    body.appendChild(logo);
  
    // Add Article Body
    obj.newBody.forEach(section => {
      const [type, ...content] = section;
      if (type === 'p') {
        const p = createEl('p');
        content.forEach(([subtype, subtext, subhref]) => {
          if (subtype === 't') {
            p.appendChild(doc.createTextNode(subtext));
          } else if (subtype === 'a') {
            const a = createEl('a', subtext, { href: subhref });
            p.appendChild(a);
          }
        });
        body.appendChild(p);
      } else if (type === 'h') {
        body.appendChild(createEl('h2', content[0]));
      } else if (type === 'i') {
        const [caption, credit, imgSrc, ...sources] = content;
        const figure = createEl('figure');
        const picture = createEl('picture');
        sources.forEach(([srcset, media]) => {
          const source = createEl('source', '', { srcset, media });
          picture.appendChild(source);
        });
        const img = createEl('img', '', { src: imgSrc });
        picture.appendChild(img);
        figure.appendChild(picture);
        figure.appendChild(createEl('figcaption', `${caption} — ${credit}`));
        body.appendChild(figure);
      } else if (type === 'm') {
        const [lat, lng, zoom] = content;
        const map = createEl('div', `Map: ${lat}, ${lng} (Zoom ${zoom})`);
        map.setAttribute('data-lat', lat);
        map.setAttribute('data-lng', lng);
        map.setAttribute('data-zoom', zoom);
        body.appendChild(map);
      } else if (type === 'r') {
        const [title, href, imgSrc] = content;
        const div = createEl('div');
        if (imgSrc) div.appendChild(createEl('img', '', { src: imgSrc }));
        div.appendChild(createEl('a', title, { href }));
        body.appendChild(div);
      }
    });
  
    return doc;
  }
  