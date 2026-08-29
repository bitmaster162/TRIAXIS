#include <bits/stdc++.h>
using namespace std;
using int64 = long long;
using i128 = __int128_t;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    long long M,C,K;
    if(!(cin>>N>>M>>C>>K)) return 0;
    vector<long long>A(N);
    for(auto &x:A) cin>>x;
    sort(A.begin(),A.end());

    i128 ans=0;
    long long t=0;
    for(long long k=0;k<K;k++){
        long long threshold = (t==0 ? M : M-t);
        auto it=lower_bound(A.begin(),A.end(),threshold);
        long long cur;
        if(it!=A.end()) cur=*it+t-M;
        else cur=A[0]+t;
        ans+=cur;
        t = (t + C) % M;
    }

    if(ans==0){ cout<<0<<'\n'; return 0; }
    string s;
    while(ans){ s.push_back(char('0'+ans%10)); ans/=10; }
    reverse(s.begin(),s.end());
    cout<<s<<'\n';
    return 0;
}
