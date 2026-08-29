#include <bits/stdc++.h>
using namespace std;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    if(!(cin>>N)) return 0;
    vector<unsigned long long>A(N);
    for(auto &x:A) cin>>x;

    int best=0;
    for(int k=0;k<N;k++){
        for(int t=0;t<=61;t++){
            unsigned long long modbit=1ULL<<(t+2);
            unsigned long long mask=modbit-1;
            unsigned long long p=1ULL<<t;
            unsigned long long c=(p-(A[k]&mask))&mask;

            int got=0;
            for(int j=0;j<N;j++){
                unsigned long long x=(c+(A[j]&mask))&mask;
                if(x==0) continue;
                int v=__builtin_ctzll(x);
                if(v<=t && ((x>>v)&3ULL)==1ULL) got++;
            }
            best=max(best,got);
        }
    }
    cout<<best<<'\n';
    return 0;
}
