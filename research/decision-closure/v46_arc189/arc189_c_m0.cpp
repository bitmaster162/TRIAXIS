#include <bits/stdc++.h>
using namespace std;

static vector<int> required_path(
    int N, int X,
    const vector<int>& init,
    const vector<int>& perm
){
    vector<int> inv(N);
    for(int i=0;i<N;i++) inv[perm[i]]=i;

    vector<int> dist(N,-1), bydist;
    dist[X]=0;
    bydist.push_back(X);
    int cur=inv[X], d=1;
    while(cur!=X){
        dist[cur]=d++;
        bydist.push_back(cur);
        cur=inv[cur];
    }

    int far=0;
    for(int i=0;i<N;i++){
        if(init[i]){
            if(dist[i]<0) return {-1};
            far=max(far,dist[i]);
        }
    }

    vector<int> seq;
    seq.reserve(far);
    for(int t=far;t>=1;--t) seq.push_back(bydist[t]);
    return seq;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N,X;
    if(!(cin>>N>>X)) return 0;
    --X;
    vector<int>A(N),B(N),P(N),Q(N);
    for(int&i:A) cin>>i;
    for(int&i:B) cin>>i;
    for(int&i:P){cin>>i;--i;}
    for(int&i:Q){cin>>i;--i;}

    auto R=required_path(N,X,A,P);
    if(R.size()==1 && R[0]==-1){
        cout<<-1<<'\n';
        return 0;
    }
    auto S=required_path(N,X,B,Q);
    if(S.size()==1 && S[0]==-1){
        cout<<-1<<'\n';
        return 0;
    }

    vector<int> pos(N,-1);
    for(int i=0;i<(int)S.size();i++) pos[S[i]]=i;

    vector<int> lis;
    for(int v:R) if(pos[v]!=-1){
        int x=pos[v];
        auto it=lower_bound(lis.begin(),lis.end(),x);
        if(it==lis.end()) lis.push_back(x);
        else *it=x;
    }

    long long ans=(long long)R.size()+S.size()-lis.size();
    cout<<ans<<'\n';
    return 0;
}
