let chart = null;
let originalData = null;

const fetchData = async () => {
    try {
        const response = await fetch('all.json');
        originalData = await response.json();
        renderChart();
    } catch (error) {
        console.error('Error fetching data:', error);
    }
};

const processData = (cumulative) => {
    if (!originalData) return { labels: [], datasets: [] };

    const ecosystems = Object.keys(originalData);
    const allMonths = [...new Set(ecosystems.flatMap(eco => Object.keys(originalData[eco])))].sort();

    const totalSeries = ecosystems.length + 1; // +1 for total

    const datasets = ecosystems.map((eco, index) => {
        const hue = (index * 360) / totalSeries;
        const color = `hsl(${hue}, 70%, 50%)`;
        const bgColor = `hsla(${hue}, 70%, 50%, 0.5)`;
        let cumulativeCount = 0;
        const dataPoints = allMonths.map(month => {
            const monthValue = originalData[eco][month] || 0;
            if (cumulative) {
                cumulativeCount += monthValue;
                return cumulativeCount;
            }
            return monthValue;
        });

        return {
            label: eco,
            data: dataPoints,
            borderColor: color,
            backgroundColor: bgColor,
            fill: false,
            hidden: false,
        };
    });

    // Add total series
    const totalData = allMonths.map((month, i) => {
        let monthTotal = 0;
        for (const dataset of datasets) {
            monthTotal += dataset.data[i];
        }
        return monthTotal;
    });

    const totalHue = (ecosystems.length * 360) / totalSeries;
    const totalColor = `hsl(${totalHue}, 70%, 50%)`;
    const totalBgColor = `hsla(${totalHue}, 70%, 50%, 0.5)`;

    datasets.push({
        label: 'Total',
        data: totalData,
        borderColor: totalColor,
        backgroundColor: totalBgColor,
        fill: false,
        hidden: true, // Hidden by default
    });

    return {
        labels: allMonths.map(m => m.substring(0, 7)),
        datasets: datasets,
    };
};

const renderChart = () => {
    const isStacked = document.getElementById('stacked-switch').checked;
    const isCumulative = document.getElementById('cumulative-switch').checked;

    const { labels, datasets } = processData(isCumulative);

    if (chart) {
        chart.destroy();
    }

    const ctx = document.getElementById('stats-chart').getContext('2d');
    chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: datasets.map(d => ({ ...d, fill: isStacked })),
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Malicious Package Reports Published per Month'
                },
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Month'
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Number of Reports'
                    },
                    beginAtZero: true,
                    stacked: isStacked,
                }
            }
        }
    });

    renderCustomLegend(chart);
};

const renderCustomLegend = (chart) => {
    const legendContainer = document.getElementById('legend-container');
    legendContainer.innerHTML = '';

    chart.data.datasets.forEach((dataset, index) => {
        const legendItem = document.createElement('div');
        legendItem.classList.add('legend-item');
        legendItem.style.backgroundColor = dataset.hidden ? '#f0f0f0' : '#fff';
        legendItem.style.textDecoration = dataset.hidden ? 'line-through' : 'none';

        const colorBox = document.createElement('span');
        colorBox.classList.add('legend-color');
        colorBox.style.backgroundColor = dataset.borderColor;

        legendItem.appendChild(colorBox);
        legendItem.appendChild(document.createTextNode(dataset.label));

        legendItem.onclick = () => {
            const meta = chart.getDatasetMeta(index);
            meta.hidden = !meta.hidden;
            legendItem.style.backgroundColor = meta.hidden ? '#f0f0f0' : '#fff';
            legendItem.style.textDecoration = meta.hidden ? 'line-through' : 'none';
            chart.update();
        };

        legendContainer.appendChild(legendItem);
    });
};

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('stacked-switch').addEventListener('change', renderChart);
    document.getElementById('cumulative-switch').addEventListener('change', renderChart);
    fetchData();
});