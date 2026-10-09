#include <bits/stdc++.h>
#include <boost/multiprecision/cpp_int.hpp>
using namespace std;
using boost::multiprecision::cpp_int;

// Exact one-shot baseline. It intentionally prioritizes semantic correctness of the
// statement transformation over scalability: every subarray sum is formed exactly.
// Claim-grade constraint safety is adjudicated only after the M0 freeze.
int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int N; if(!(cin>>N)) return 0;
    vector<int>A(N);
    for(int &x:A) cin>>x;
    long long ans=0;
    for(int l=0;l<N;l++){
        cpp_int s=0;
        for(int r=l;r<N;r++){
            s += (cpp_int(1) << A[r]);
            if(s>0 && (s & (s-1))==0) ++ans;
        }
    }
    cout<<ans<<'\n';
    return 0;
}
