#include <bits/stdc++.h>
using namespace std;

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int T;
    cin >> T;
    while (T--) {
        int N;
        cin >> N;
        vector<int> a(N + 1);
        set<int> unassigned;
        set<int> ones;
        set<pair<int,int>> assigned_by_value; // (a_i, i)

        for (int i = 1; i <= N; ++i) {
            cin >> a[i];
            if (a[i] == -1) {
                a[i] = 0;
                unassigned.insert(i);
            } else {
                assigned_by_value.insert({a[i], i});
                if (a[i] == 1) ones.insert(i);
            }
        }

        vector<int> b(N + 1);

        auto assign_value = [&](int idx, int val) {
            if (a[idx] != 0) return;
            unassigned.erase(idx);
            a[idx] = val;
            assigned_by_value.insert({val, idx});
            if (val == 1) ones.insert(idx);
        };

        for (int i = 1; i <= N; ++i) {
            if (a[i] != 0) {
                int j = a[i];
                if (a[j] == 0) assign_value(j, 1);
                b[i] = a[j];
                continue;
            }

            int best_target = INT_MAX;

            if (!ones.empty()) best_target = min(best_target, *ones.begin());

            auto it = unassigned.begin();
            if (it != unassigned.end() && *it == i) ++it;
            if (it != unassigned.end()) best_target = min(best_target, *it);

            if (i == 1) best_target = min(best_target, 1);

            if (best_target != INT_MAX) {
                if (best_target == i) {
                    assign_value(i, i); // only possible beneficial self-choice is i=1
                    b[i] = i;
                } else {
                    if (a[best_target] == 0) assign_value(best_target, 1);
                    assign_value(i, best_target);
                    b[i] = a[best_target];
                }
                continue;
            }

            // i is the only remaining unassigned position and there is no position with value 1.
            pair<int,int> best = {i, i}; // choose a_i=i, then b_i=i
            if (!assigned_by_value.empty()) {
                auto q = *assigned_by_value.begin(); // minimizes (a_j, j)
                best = min(best, {q.first, q.second});
            }
            int target = best.second;
            assign_value(i, target);
            b[i] = (target == i ? i : a[target]);
        }

        for (int i = 1; i <= N; ++i) {
            if (i > 1) cout << ' ';
            cout << b[i];
        }
        cout << '\n';
    }
    return 0;
}
