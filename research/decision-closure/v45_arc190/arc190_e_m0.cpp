#include <bits/stdc++.h>
using namespace std;
using int64 = long long;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int N,Q;
    if(!(cin>>N>>Q)) return 0;
    vector<int64>A(N);
    for(auto &x:A) cin>>x;
    while(Q--){
        int L,R; cin>>L>>R; --L; --R;
        vector<int64> b(A.begin()+L, A.begin()+R+1);
        int64 ans=0;
        int m=b.size();
        for(int i=0;i<m;i++){
            if(i+2<m){
                int64 z=min(b[i],b[i+2]);
                b[i]-=z; b[i+2]-=z; ans+=z;
            }
            if(i+1<m){
                int64 z=min(b[i],b[i+1]);
                b[i]-=z; b[i+1]-=z; ans+=z;
            }
        }
        cout<<ans<<'\n';
    }
}
