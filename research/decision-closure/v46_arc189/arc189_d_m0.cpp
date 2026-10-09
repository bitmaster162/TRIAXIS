#include <bits/stdc++.h>
using namespace std;
using int64 = long long;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    if(!(cin>>N)) return 0;
    vector<int64>A(N);
    for(auto &x:A) cin>>x;

    vector<int> par(N,-1), lc(N,-1), rc(N,-1), st;
    st.reserve(N);

    // Max Cartesian tree. Equal maxima are resolved to the later index.
    for(int i=0;i<N;i++){
        int last=-1;
        while(!st.empty() && A[st.back()]<=A[i]){
            last=st.back();
            st.pop_back();
        }
        if(!st.empty()) rc[st.back()]=i;
        if(last!=-1) lc[i]=last;
        st.push_back(i);
    }
    int root=st.front();

    fill(par.begin(),par.end(),-1);
    for(int u=0;u<N;u++){
        if(lc[u]!=-1) par[lc[u]]=u;
        if(rc[u]!=-1) par[rc[u]]=u;
    }

    vector<int> order;
    order.reserve(N);
    st.clear();
    st.push_back(root);
    while(!st.empty()){
        int u=st.back(); st.pop_back();
        order.push_back(u);
        if(lc[u]!=-1) st.push_back(lc[u]);
        if(rc[u]!=-1) st.push_back(rc[u]);
    }

    vector<int64> sum(N);
    vector<int> L(N),R(N);
    for(int it=N-1;it>=0;--it){
        int u=order[it];
        sum[u]=A[u];
        L[u]=R[u]=u;
        if(lc[u]!=-1){
            sum[u]+=sum[lc[u]];
            L[u]=L[lc[u]];
        }
        if(rc[u]!=-1){
            sum[u]+=sum[rc[u]];
            R[u]=R[rc[u]];
        }
    }

    // climb[u] = highest ancestor reachable after the whole subtree(u)
    // has already been absorbed.
    vector<int> climb(N);
    climb[root]=root;
    for(int u:order){
        if(u==root) continue;
        int p=par[u];
        if(sum[u]>A[p]) climb[u]=climb[p];
        else climb[u]=u;
    }

    vector<int64> ans(N);
    for(int u=0;u<N;u++){
        bool ready=(L[u]==R[u]);
        if(u-1>=L[u] && A[u-1]<A[u]) ready=true;
        if(u+1<=R[u] && A[u+1]<A[u]) ready=true;
        if(!ready) ans[u]=A[u];
        else ans[u]=sum[climb[u]];
    }

    for(int i=0;i<N;i++){
        if(i) cout<<' ';
        cout<<ans[i];
    }
    cout<<'\n';
    return 0;
}
