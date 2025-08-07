use once_cell::sync::Lazy;

const fn gen_sbox() -> [u8; 256] {
    let mut sbox = [0; 256];

    let mut p = 1u8;
    let mut q = 1u8;

    loop {
        // Multiply by 3 GF(2^8)
        p = p ^ (p << 1) ^ (if p & 0x80 != 0 { 0x1b } else { 0 });

        // Divide by 3 in GF(2^8)
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= if q & 0x80 != 0 { 0x09 } else { 0 };

        // affine transform
        let xformed =
            q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4) ^ 0x63;

        sbox[p as usize] = xformed;

        if p == 1 {
            break;
        }
    }

    sbox[0] = 0x63;

    sbox
}

const fn gen_inv_sbox() -> [u8; 256] {
    let mut res = [0; 256];
    let mut i: usize = 0;

    while i < 256 {
        res[SBOX[i] as usize] = i as u8;
        i += 1;
    }

    res
}

// 1 5 0 2 4 3
// 5 3 1 0 4 2

/// The sbox (substitution box) used in AES defines a swapping of elements. The byte a<sub>i,j</sub>
/// is replaced with the byte S(a<sub>i,j</sub>). The result is always:<br>
/// <table>
/// 	<tr><th></th><th>00</th><th>01</th><th>02</th><th>03</th><th>04</th><th>05</th><th>06</th><th>07</th><th>08</th><th>09</th><th>0a</th><th>0b</th><th>0c</th><th>0d</th><th>0e</th><th>0f</th>
/// 	<tr><th>00</th><td>63</td><td>7c</td><td>77</td><td>7b</td><td>f2</td><td>6b</td><td>6f</td><td>c5</td><td>30</td><td>01</td><td>67</td><td>2b</td><td>fe</td><td>d7</td><td>ab</td><td>76</td></tr>
/// 	<tr><th>10</th><td>ca</td><td>82</td><td>c9</td><td>7d</td><td>fa</td><td>59</td><td>47</td><td>f0</td><td>ad</td><td>d4</td><td>a2</td><td>af</td><td>9c</td><td>a4</td><td>72</td><td>c0</td></tr>
/// 	<tr><th>20</th><td>b7</td><td>fd</td><td>93</td><td>26</td><td>36</td><td>3f</td><td>f7</td><td>cc</td><td>34</td><td>a5</td><td>e5</td><td>f1</td><td>71</td><td>d8</td><td>31</td><td>15</td></tr>
/// 	<tr><th>30</th><td>04</td><td>c7</td><td>23</td><td>c3</td><td>18</td><td>96</td><td>05</td><td>9a</td><td>07</td><td>12</td><td>80</td><td>e2</td><td>eb</td><td>27</td><td>b2</td><td>75</td></tr>
/// 	<tr><th>40</th><td>09</td><td>83</td><td>2c</td><td>1a</td><td>1b</td><td>6e</td><td>5a</td><td>a0</td><td>52</td><td>3b</td><td>d6</td><td>b3</td><td>29</td><td>e3</td><td>2f</td><td>84</td></tr>
/// 	<tr><th>50</th><td>53</td><td>d1</td><td>00</td><td>ed</td><td>20</td><td>fc</td><td>b1</td><td>5b</td><td>6a</td><td>cb</td><td>be</td><td>39</td><td>4a</td><td>4c</td><td>58</td><td>cf</td></tr>
/// 	<tr><th>60</th><td>d0</td><td>ef</td><td>aa</td><td>fb</td><td>43</td><td>4d</td><td>33</td><td>85</td><td>45</td><td>f9</td><td>02</td><td>7f</td><td>50</td><td>3c</td><td>9f</td><td>a8</td></tr>
/// 	<tr><th>70</th><td>51</td><td>a3</td><td>40</td><td>8f</td><td>92</td><td>9d</td><td>38</td><td>f5</td><td>bc</td><td>b6</td><td>da</td><td>21</td><td>10</td><td>ff</td><td>f3</td><td>d2</td></tr>
/// 	<tr><th>80</th><td>cd</td><td>0c</td><td>13</td><td>ec</td><td>5f</td><td>97</td><td>44</td><td>17</td><td>c4</td><td>a7</td><td>7e</td><td>3d</td><td>64</td><td>5d</td><td>19</td><td>73</td></tr>
/// 	<tr><th>90</th><td>60</td><td>81</td><td>4f</td><td>dc</td><td>22</td><td>2a</td><td>90</td><td>88</td><td>46</td><td>ee</td><td>b8</td><td>14</td><td>de</td><td>5e</td><td>0b</td><td>db</td></tr>
/// 	<tr><th>a0</th><td>e0</td><td>32</td><td>3a</td><td>0a</td><td>49</td><td>06</td><td>24</td><td>5c</td><td>c2</td><td>d3</td><td>ac</td><td>62</td><td>91</td><td>95</td><td>e4</td><td>79</td></tr>
/// 	<tr><th>b0</th><td>e7</td><td>c8</td><td>37</td><td>6d</td><td>8d</td><td>d5</td><td>4e</td><td>a9</td><td>6c</td><td>56</td><td>f4</td><td>ea</td><td>65</td><td>7a</td><td>ae</td><td>08</td></tr>
/// 	<tr><th>c0</th><td>ba</td><td>78</td><td>25</td><td>2e</td><td>1c</td><td>a6</td><td>b4</td><td>c6</td><td>e8</td><td>dd</td><td>74</td><td>1f</td><td>4b</td><td>bd</td><td>8b</td><td>8a</td></tr>
/// 	<tr><th>d0</th><td>70</td><td>3e</td><td>b5</td><td>66</td><td>48</td><td>03</td><td>f6</td><td>0e</td><td>61</td><td>35</td><td>57</td><td>b9</td><td>86</td><td>c1</td><td>1d</td><td>9e</td></tr>
/// 	<tr><th>e0</th><td>e1</td><td>f8</td><td>98</td><td>11</td><td>69</td><td>d9</td><td>8e</td><td>94</td><td>9b</td><td>1e</td><td>87</td><td>e9</td><td>ce</td><td>55</td><td>28</td><td>df</td></tr>
/// 	<tr><th>f0</th><td>8c</td><td>a1</td><td>89</td><td>0d</td><td>bf</td><td>e6</td><td>42</td><td>68</td><td>41</td><td>99</td><td>2d</td><td>0f</td><td>b0</td><td>54</td><td>bb</td><td>16</td></tr>
/// </table>
pub const SBOX: [u8; 256] = gen_sbox();

/// The inv_sbox (inverse substitution box) is used in AES decryption and is able to reverse the
/// sub_bytes step. invS(S(a<sub>i,j</sub>)) = a<sub>i,j</sub>. The result is always:
/// <table>
/// 	<tr><th></th><th>00</th><th>01</th><th>02</th><th>03</th><th>04</th><th>05</th><th>06</th><th>07</th><th>08</th><th>09</th><th>0a</th><th>0b</th><th>0c</th><th>0d</th><th>0e</th><th>0f</th></tr>
/// 	<tr><th>00</th><td>52</td><td>09</td><td>6a</td><td>d5</td><td>30</td><td>36</td><td>a5</td><td>38</td><td>bf</td><td>40</td><td>a3</td><td>9e</td><td>81</td><td>f3</td><td>d7</td><td>fb</td></tr>
/// 	<tr><th>10</th><td>7c</td><td>e3</td><td>39</td><td>82</td><td>9b</td><td>2f</td><td>ff</td><td>87</td><td>34</td><td>8e</td><td>43</td><td>44</td><td>c4</td><td>de</td><td>e9</td><td>cb</td></tr>
/// 	<tr><th>20</th><td>54</td><td>7b</td><td>94</td><td>32</td><td>a6</td><td>c2</td><td>23</td><td>3d</td><td>ee</td><td>4c</td><td>95</td><td>0b</td><td>42</td><td>fa</td><td>c3</td><td>4e</td></tr>
/// 	<tr><th>30</th><td>08</td><td>2e</td><td>a1</td><td>66</td><td>28</td><td>d9</td><td>24</td><td>b2</td><td>76</td><td>5b</td><td>a2</td><td>49</td><td>6d</td><td>8b</td><td>d1</td><td>25</td></tr>
/// 	<tr><th>40</th><td>72</td><td>f8</td><td>f6</td><td>64</td><td>86</td><td>68</td><td>98</td><td>16</td><td>d4</td><td>a4</td><td>5c</td><td>cc</td><td>5d</td><td>65</td><td>b6</td><td>92</td></tr>
/// 	<tr><th>50</th><td>6c</td><td>70</td><td>48</td><td>50</td><td>fd</td><td>ed</td><td>b9</td><td>da</td><td>5e</td><td>15</td><td>46</td><td>57</td><td>a7</td><td>8d</td><td>9d</td><td>84</td></tr>
/// 	<tr><th>60</th><td>90</td><td>d8</td><td>ab</td><td>00</td><td>8c</td><td>bc</td><td>d3</td><td>0a</td><td>f7</td><td>e4</td><td>58</td><td>05</td><td>b8</td><td>b3</td><td>45</td><td>06</td></tr>
/// 	<tr><th>70</th><td>d0</td><td>2c</td><td>1e</td><td>8f</td><td>ca</td><td>3f</td><td>0f</td><td>02</td><td>c1</td><td>af</td><td>bd</td><td>03</td><td>01</td><td>13</td><td>8a</td><td>6b</td></tr>
/// 	<tr><th>80</th><td>3a</td><td>91</td><td>11</td><td>41</td><td>4f</td><td>67</td><td>dc</td><td>ea</td><td>97</td><td>f2</td><td>cf</td><td>ce</td><td>f0</td><td>b4</td><td>e6</td><td>73</td></tr>
/// 	<tr><th>90</th><td>96</td><td>ac</td><td>74</td><td>22</td><td>e7</td><td>ad</td><td>35</td><td>85</td><td>e2</td><td>f9</td><td>37</td><td>e8</td><td>1c</td><td>75</td><td>df</td><td>6e</td></tr>
/// 	<tr><th>a0</th><td>47</td><td>f1</td><td>1a</td><td>71</td><td>1d</td><td>29</td><td>c5</td><td>89</td><td>6f</td><td>b7</td><td>62</td><td>0e</td><td>aa</td><td>18</td><td>be</td><td>1b</td></tr>
/// 	<tr><th>b0</th><td>fc</td><td>56</td><td>3e</td><td>4b</td><td>c6</td><td>d2</td><td>79</td><td>20</td><td>9a</td><td>db</td><td>c0</td><td>fe</td><td>78</td><td>cd</td><td>5a</td><td>f4</td></tr>
/// 	<tr><th>c0</th><td>1f</td><td>dd</td><td>a8</td><td>33</td><td>88</td><td>07</td><td>c7</td><td>31</td><td>b1</td><td>12</td><td>10</td><td>59</td><td>27</td><td>80</td><td>ec</td><td>5f</td></tr>
/// 	<tr><th>d0</th><td>60</td><td>51</td><td>7f</td><td>a9</td><td>19</td><td>b5</td><td>4a</td><td>0d</td><td>2d</td><td>e5</td><td>7a</td><td>9f</td><td>93</td><td>c9</td><td>9c</td><td>ef</td></tr>
/// 	<tr><th>e0</th><td>a0</td><td>e0</td><td>3b</td><td>4d</td><td>ae</td><td>2a</td><td>f5</td><td>b0</td><td>c8</td><td>eb</td><td>bb</td><td>3c</td><td>83</td><td>53</td><td>99</td><td>61</td></tr>
/// 	<tr><th>f0</th><td>17</td><td>2b</td><td>04</td><td>7e</td><td>ba</td><td>77</td><td>d6</td><td>26</td><td>e1</td><td>69</td><td>14</td><td>63</td><td>55</td><td>21</td><td>0c</td><td>7d</td></tr>
// </table>
pub const INV_SBOX: [u8; 256] = gen_inv_sbox();
