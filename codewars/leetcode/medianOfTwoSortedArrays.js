// 4. Median of Two Sorted Arrays

// Given two sorted arrays nums1 and nums2 of size m and n respectively,
// return the median of the two sorted arrays.

// The overall run time complexity should be O(log (m+n)).

// Example 1:
// Input: nums1 = [1,3], nums2 = [2]
// Output: 2.00000
// Explanation: merged array = [1,2,3] and median is 2.

// Example 2:
// Input: nums1 = [1,2], nums2 = [3,4]
// Output: 2.50000
// Explanation: merged array = [1,2,3,4] and median is (2 + 3) / 2 = 2.5.

// Constraints:
// nums1.length == m
// nums2.length == n
// 0 <= m <= 1000
// 0 <= n <= 1000
// 1 <= m + n <= 2000
// -10^6 <= nums1[i], nums2[i] <= 10^6

/* My Solution - Binary Search on the smaller array, O(log(min(m,n))) */

/**
 * @param {number[]} nums1
 * @param {number[]} nums2
 * @return {number}
 */
var findMedianSortedArrays = function(nums1, nums2) {
    // Always binary search on the shorter array for O(log(min(m,n)))
    if (nums1.length > nums2.length) {
        return findMedianSortedArrays(nums2, nums1);
    }

    const m = nums1.length;
    const n = nums2.length;
    const halfLen = Math.floor((m + n + 1) / 2);

    let left = 0;
    let right = m;

    while (left <= right) {
        // Partition nums1 at i, nums2 at j
        const i = Math.floor((left + right) / 2);
        const j = halfLen - i;

        // Edge values on either side of each partition
        const nums1LeftMax  = i === 0 ? -Infinity : nums1[i - 1];
        const nums1RightMin = i === m ?  Infinity : nums1[i];
        const nums2LeftMax  = j === 0 ? -Infinity : nums2[j - 1];
        const nums2RightMin = j === n ?  Infinity : nums2[j];

        if (nums1LeftMax <= nums2RightMin && nums2LeftMax <= nums1RightMin) {
            // Correct partition found
            if ((m + n) % 2 === 1) {
                // Odd total - median is max of left side
                return Math.max(nums1LeftMax, nums2LeftMax);
            }
            // Even total - median is average of the two middle values
            return (Math.max(nums1LeftMax, nums2LeftMax) +
                    Math.min(nums1RightMin, nums2RightMin)) / 2;
        } else if (nums1LeftMax > nums2RightMin) {
            // Too far right in nums1, shift left
            right = i - 1;
        } else {
            // Too far left in nums1, shift right
            left = i + 1;
        }
    }

    return 0.0; // unreachable with valid input
};
