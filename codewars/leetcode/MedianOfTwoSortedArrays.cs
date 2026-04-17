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

public class Solution
{
    public double FindMedianSortedArrays(int[] nums1, int[] nums2)
    {
        // Always binary search on the shorter array for O(log(min(m,n)))
        if (nums1.Length > nums2.Length)
        {
            return FindMedianSortedArrays(nums2, nums1);
        }

        int m = nums1.Length;
        int n = nums2.Length;
        int halfLen = (m + n + 1) / 2;

        int left = 0;
        int right = m;

        while (left <= right)
        {
            // Partition nums1 at i, nums2 at j
            int i = (left + right) / 2;
            int j = halfLen - i;

            // Edge values on either side of each partition
            int nums1LeftMax  = i == 0 ? int.MinValue : nums1[i - 1];
            int nums1RightMin = i == m ? int.MaxValue : nums1[i];
            int nums2LeftMax  = j == 0 ? int.MinValue : nums2[j - 1];
            int nums2RightMin = j == n ? int.MaxValue : nums2[j];

            if (nums1LeftMax <= nums2RightMin && nums2LeftMax <= nums1RightMin)
            {
                // Correct partition found
                if ((m + n) % 2 == 1)
                {
                    // Odd total - median is max of left side
                    return System.Math.Max(nums1LeftMax, nums2LeftMax);
                }
                // Even total - median is average of the two middle values
                return (System.Math.Max(nums1LeftMax, nums2LeftMax) +
                        System.Math.Min(nums1RightMin, nums2RightMin)) / 2.0;
            }
            else if (nums1LeftMax > nums2RightMin)
            {
                // Too far right in nums1, shift left
                right = i - 1;
            }
            else
            {
                // Too far left in nums1, shift right
                left = i + 1;
            }
        }

        return 0.0; // unreachable with valid input
    }
}
