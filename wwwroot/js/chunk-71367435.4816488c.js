(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-71367435"],{a55b:function(o,t,e){"use strict";e.r(t);var a=function(){var o=this,t=o.$createElement,e=o._self._c||t;return e("a-layout",{attrs:{id:"login"}},[e("a-layout-content",[e("a-form-model",{ref:"loginRef",attrs:{model:o.loginModal.model,rules:o.loginModal.rules}},[e("a-row",{attrs:{gutter:24}},[e("a-col",{attrs:{span:24}},[e("a-form-model-item",[e("h1",[o._v("LOGIN")]),e("span",[o._v("LOGIN DESCRIPTION")])])],1),e("a-col",{attrs:{span:24}},[e("a-form-model-item",{attrs:{prop:"account"}},[e("a-input",{attrs:{placeholder:"please enter your account"},model:{value:o.loginModal.model.account,callback:function(t){o.$set(o.loginModal.model,"account",t)},expression:"loginModal.model.account"}},[e("a-icon",{staticStyle:{color:"rgba(0,0,0,.45)"},attrs:{slot:"prefix",type:"form"},slot:"prefix"})],1)],1)],1),e("a-col",{attrs:{span:24}},[e("a-form-model-item",{attrs:{prop:"password"}},[e("a-input-password",{attrs:{placeholder:"please enter your password"},model:{value:o.loginModal.model.password,callback:function(t){o.$set(o.loginModal.model,"password",t)},expression:"loginModal.model.password"}},[e("a-icon",{staticStyle:{color:"rgba(0,0,0,.45)"},attrs:{slot:"prefix",type:"form"},slot:"prefix"})],1)],1)],1),e("a-col",{attrs:{span:24}},[e("a-row",{attrs:{gutter:24}},[e("a-col",{attrs:{span:24}},[e("a-checkbox",{staticStyle:{"padding-top":"1px","margin-bottom":"26px"},model:{value:o.loginModal.model.remember,callback:function(t){o.$set(o.loginModal.model,"remember",t)},expression:"loginModal.model.remember"}},[o._v(" Remember ")])],1)],1)],1),e("a-col",{attrs:{span:24}},[e("a-form-model-item",[e("a-button",{attrs:{block:"",type:"primary",loading:o.loginModal.confirmLoading},on:{click:o.loginCommit}},[o._v("LOGIN")])],1)],1)],1)],1)],1)],1)},n=[],r=e("ff66"),l={name:"Login",data:function(){return{loginModal:{confirmLoading:!1,model:{account:"",password:"",remember:!1},rules:{account:[{required:!0,message:"required",trigger:"blur"}],password:[{required:!0,message:"required",trigger:"blur"}]}}}},methods:{loginCommit:function(){var o=this;this.$refs.loginRef.validate((function(t){t&&(o.loginModal.confirmLoading=!0,Object(r["c"])(o.loginModal.model).then((function(t){o.$store.commit("TOKEN",t.data.token),o.$store.commit("TOKEN_EXPIRE_TIME",t.data.tokenExpireTime),o.$store.commit("TOKEN_REFRESH_EXPIRE_TIME",t.data.tokenRefreshExpireTime)})).then((function(t){Object(r["a"])().then((function(t){o.$store.commit("PROFILE",t.data)})),Object(r["b"])().then((function(t){o.$store.commit("RESOURCE",t.data)}))})).then((function(t){o.$router.push({name:"Main"})})).catch((function(t){o.loginModal.confirmLoading=!1,o.loginModal.model.password=""})))}))}}},i=l,s=(e("d6db"),e("2877")),c=Object(s["a"])(i,a,n,!1,null,null,null);t["default"]=c.exports},d6db:function(o,t,e){"use strict";e("e67a")},e67a:function(o,t,e){}}]);
//# sourceMappingURL=chunk-71367435.4816488c.js.map