#include <bits/stdc++.h>
using namespace std;
using int64 = long long;
static const int64 INF = (1LL<<60);

static int64 nearest_cost(const vector<int64>& v, int64 x){
    if(v.empty()) return INF;
    auto it=lower_bound(v.begin(),v.end(),x);
    int64 ans=INF;
    if(it!=v.end()) ans=min(ans, llabs(*it-x));
    if(it!=v.begin()) { --it; ans=min(ans,llabs(*it-x)); }
    return ans;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int L,N;
    cin >> L >> N;
    string S; cin >> S;
    vector<int64> pA(L+1,0), pJ(L+1,0);
    for(int i=1;i<=L;i++){
        pA[i]=pA[i-1]+(S[i-1]=='J');
        pJ[i]=pJ[i-1]+(S[i-1]=='A');
    }
    vector<int64> srcA, srcJ;
    for(int i=0;i<N;i++){
        int x; char c; cin >> x >> c;
        if(c=='A') srcA.push_back(pA[x]);
        else srcJ.push_back(pJ[x]);
    }
    sort(srcA.begin(),srcA.end());
    sort(srcJ.begin(),srcJ.end());

    int64 dpA=nearest_cost(srcA,pA[0]);
    int64 dpJ=nearest_cost(srcJ,pJ[0]);
    for(int x=0;x<L;x++){
        int64 gA=nearest_cost(srcA,pA[x]);
        int64 gJ=nearest_cost(srcJ,pJ[x]);
        int64 nA=dpA, nJ=dpJ;
        if(dpJ<INF/4 && gA<INF/4) nA=min(nA,dpJ+gA);
        if(dpA<INF/4 && gJ<INF/4) nJ=min(nJ,dpA+gJ);
        dpA = (nA>=INF/4 ? INF : nA + (S[x]=='J'));
        dpJ = (nJ>=INF/4 ? INF : nJ + (S[x]=='A'));
    }
    cout << min(dpA,dpJ) << '\n';
    return 0;
}
