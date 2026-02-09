import { a as createServerFn, b as createSsrRpc } from "../server.js";
import { a as authMiddleware } from "./auth-middleware-Bbw8ptVi.js";
const getUiConfig = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).handler(createSsrRpc("911819bcdb0ac36df37529995fbcc19319f1c13d411900322765b0b4689b6866"));
const optionalBaseUrlInput = (input) => input;
const listTenants = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("7d1a3f2af301fa41e490368f34e8f8ae0e023376272e5b7ac61e60058bac7fc8"));
const listSubscriptions = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("c17ddf115d90cefc85f473daf8f20cdfdd867d5d820175d0b75dec148a580824"));
const createTenant = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("dc593bf19a58f90a9ef7d91fc3ff660548f04d725398ce4e2b726ba87ed08215"));
const getTenantDetail = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("c033dd462548d27447f8832a9453c6309e8118540920eeedf3890d19468800e1"));
createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("a622107254c770bdbd2e7ecb7020f047b0e88c3cb653041ff9dce5d41d892c9a"));
const getPlatformOverview = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("b33359e75789a3827c72557916ba7a42a77edc25f32840131f88b83d62bbba40"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("6e790c4843fa64087b09ea889d35fd2e8cdc0528e5b11a3c7e5f4662d874e863"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("5aba7518da0ee86bc4b21f1387f4ef7ef67de6189c9bf000d68952120cbb0b67"));
const listFeatureFlags = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("2d1974e77be9521065178bba432c7ee8a925d552f6a5f0276a6d638df8be4e3a"));
const updateFeatureFlag = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("e815b707c6424f3284f4beb7f77f61b1b488727e9d69ed5ad25eb3991d841dab"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator(optionalBaseUrlInput).handler(createSsrRpc("f64805bca92b126ddfe2186a93600233eb5dac7711eeeedf9005a6d6d152f545"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("57ae7773025d2d02b9b4d337bf0f49633e23f9d9f49d2556ec828780ee4784ae"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("cce320e10e1a8e65e57e2a6b3f3beadb719dd70297c52668726fc81ef5ff743d"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator(optionalBaseUrlInput).handler(createSsrRpc("94db58d8167408f3279f7071fedc83f32279d5a2f1b067913bbebfddd43f95ea"));
createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("caf715d889b2bc776f8384bd2e654c78eed939be8bffaeb36475f57e3b604c74"));
createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("4c8adbf2bdd9a5eed2f49d44acb7e4c32832d8a6a5a5c570d514360807da981d"));
const listApiKeys = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator(optionalBaseUrlInput).handler(createSsrRpc("4f6ae767327a0a1bea64094162ea2025b3ffbad335386eaf6786cd234d8abfbc"));
const createApiKey = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("396af684ee9b727d29a146d6c5a4aeddc6acb2e5a8cb1554b324756d218cf816"));
const deleteApiKey = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("11393555b2981f30bac815a3639e326fc9d92a779e6f704fa01896197e6a2385"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator(optionalBaseUrlInput).handler(createSsrRpc("bd0dd0a37253ba5c75a0fe75533ebfe5dc5882902a083a90829941a4285551f7"));
createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("d2a3ef54ab9d79e273211fd40725d3f56959510c1d1f8b5dee6a1dbfb61a3cdd"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator(optionalBaseUrlInput).handler(createSsrRpc("13e11b3b84a0ce0a939c985ef8c9ddab2d51685946b03864fbe985841da9bf4e"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator(optionalBaseUrlInput).handler(createSsrRpc("34bc7b65748fbdc2a5b7a3f9d8c53f227faf65c469130d4ea732c4c2fc7d3d70"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator(optionalBaseUrlInput).handler(createSsrRpc("e371a416bea511d55a8582ecc0694c224f1a9ad7d9045f37943f920ebb431039"));
const listPlatformInvoices = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("5712a129ee0706a23bdfae0ed0e8a7ae984787e2e35da1aa75c73801a2f204bd"));
createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("77e5f5691ce2dd50a3ce2eeebaa0957eacbc8916d5276f38090ff1db9835ef4f"));
const suspendTenant = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("1f0cb82e8b0fdf3f27529d6d0650e6a5afd677f7094ac88451fa184d0fc32a5c"));
const activateTenant = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("06e1013355e060cedec5dc139f3bc60dace737992ee136c376dcc772e9288476"));
createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("8253edfece41c96365eedab52199fc01ee193962b935f88fc3178f10d3f47220"));
const deleteTenant = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("3f953bf1783c56e47338ca1a36de00c411a55923561ecb1c21c8509ab79914e0"));
createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("900a121f7b0003a30714380df8a7cb4ea9927fda9130796bec5b0981533898f7"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("bd68d543ffba4fce418155a90da2d6283713bf27a3bb77bfc11e2b373fdd8150"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("a22e95df85e1fd83c6049d7e397debc0eaa965fc4a65df8650d7f990655e2f0e"));
createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(createSsrRpc("bd6fedde815c5158f58327da98a5cc46dd2a9ce1c6d90216a3ec2801c61ee5df"));
createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(createSsrRpc("c83c165d725911da0a2d10bf9b4081d342982df3a4a1cb0005f655a148062e88"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).handler(createSsrRpc("1db4956858288ffaf948aceb54510258587a817b9ce0750abd62db2175097a61"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("52b693a0d0986e1b88869bd1b2f3ad89e5d0066ab74e4dc3b53ff5f92fd9314a"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("0f40640e3b35c0977bf78642588eb873c46fdfa614fe6b4a91a15d9d91bda51d"));
const startSupportAccess = createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("ef4489f82e4ef0ce219ae7a9b56b3b3c61fd9b842a7376232e9b8046f9afbdf6"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("6d9490c0c432df4251a7d52485a35b448c5bff7b22fdb0771bd5580cf8ccd7d8"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("7273cb9ae21e0bb8f300e33243997012cf97c42bad0bf197c607d6b928aa4150"));
createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("54f8fdc888d08350069efc99121699c8efa87fb365dee638a76d1e2f59c57a1d"));
createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("4b8a4daffd0487a0d003502250d7dd39379b6b21051fb1c978158f903b409bf3"));
createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("dbd497d57b4769250296a5de412468c69252ee7f47bef6fb4858b229559deb1f"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("d98bf557f1dfc717daa594ce2281a4c9454d73de531aab0f763a0a4e437597eb"));
createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("1d8cf0c1f7ffb5c4c9d0ccfa63df3184a4f7c45be9c23383a462d2e42f27f19a"));
createServerFn({
  method: "POST"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("6bd180350339b5221bbb88c76c6a1013471b157f53c4e1c6d1b8129ba4ba6ab2"));
const listAudit = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("6d352a760c71daf1174415b290eaab48a92bc397ed28ccf5771c2cf812599c50"));
const downloadAudit = createServerFn({
  method: "GET"
}).middleware([authMiddleware]).inputValidator((input) => input).handler(createSsrRpc("ab7f74ca296f30837046b9fdde3f12fdf7677a0d74b968ecbd5a87da248443ee"));
export {
  listAudit as a,
  getPlatformOverview as b,
  listTenants as c,
  downloadAudit as d,
  deleteTenant as e,
  activateTenant as f,
  getUiConfig as g,
  listSubscriptions as h,
  createTenant as i,
  getTenantDetail as j,
  startSupportAccess as k,
  listFeatureFlags as l,
  listApiKeys as m,
  createApiKey as n,
  deleteApiKey as o,
  listPlatformInvoices as p,
  suspendTenant as s,
  updateFeatureFlag as u
};
